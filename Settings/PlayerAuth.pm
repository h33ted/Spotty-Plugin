package Plugins::Spotty::Settings::PlayerAuth;

use strict;
use base qw(Slim::Web::Settings);

use File::Spec::Functions qw(catfile);
use HTTP::Status qw(RC_MOVED_TEMPORARILY);
use JSON::XS qw(encode_json decode_json);
use Proc::Background;

use Slim::Utils::Log;
use Slim::Utils::Prefs;
use Slim::Utils::Strings qw(string);
use Slim::Utils::Timers;

use Plugins::Spotty::Plugin;
use Plugins::Spotty::AccountHelper;

use constant AUTHENTICATE => '__AUTHENTICATE__';
use constant HELPER_TIMEOUT => 60*15;		# kill the helper application after 15 minutes
use constant RESTART_DELAY => 30;			# don't restart a failing helper more often than this

my $prefs = preferences('plugin.spotty');
my $log   = logger('plugin.spotty');
my $helper;
my $lastStart = 0;
my $lastError = '';

sub new {
	my $class = shift;

	Slim::Web::Pages->addPageFunction($class->page, $class);
	Slim::Web::Pages->addRawFunction("plugins/Spotty/settings/hasPlayerCredentials", \&checkCredentials);
}

sub name {
	return Slim::Web::HTTP::CSRF->protectName('PLUGIN_SPOTTY');
}

sub page {
	return Slim::Web::HTTP::CSRF->protectURI('plugins/Spotty/settings/player-auth.html');
}

sub prefs {
	return ($prefs, 'helper');
}

sub handler {
	my ($class, $client, $paramRef, $pageSetup, $httpClient, $response) = @_;

	my ($helperPath, $helperVersion) = Plugins::Spotty::Helper->get();

	if ( Plugins::Spotty::AccountHelper->hasPlayerCredentials() ) {
		$class->shutdownHelper;

		$response->code(RC_MOVED_TEMPORARILY);
		$response->header('Location' => 'basic.html');
		return Slim::Web::HTTP::filltemplatefile($class->page, $paramRef);
	}

	if ( !$class->startHelper() ) {
		$paramRef->{helperMissing} = $helperPath || 1;
	}

	my $helpers = Plugins::Spotty::Helper->getAll();

	if ($helpers && scalar keys %$helpers > 1) {
		$paramRef->{helpers} = $helpers;
	}

	$paramRef->{deviceAuth}     = Plugins::Spotty::Helper->getCapability('device-auth') ? 1 : 0;
	$paramRef->{helperPath}     = $helperPath;
	$paramRef->{helperVersion}  = $helperVersion ? "v$helperVersion" : string('PLUGIN_SPOTTY_HELPER_ERROR');

	return $class->SUPER::handler($client, $paramRef);
}

# Some custom page handlers for advanced stuff

# check whether we have credentials - called by the web page to decide if it can return
sub checkCredentials {
	my ($httpClient, $response, $func) = @_;

	my $request = $response->request;

	my $result = {
		hasCredentials => Plugins::Spotty::AccountHelper->hasPlayerCredentials()
	};

	if ($result->{hasCredentials}) {
		__PACKAGE__->shutdownHelper();
	}
	else {
		# make sure our authentication helper is running
		__PACKAGE__->startHelper();

		if (my $deviceAuth = __PACKAGE__->getDeviceAuth()) {
			$result->{deviceAuth} = $deviceAuth;
		}
	}

	my $content = encode_json($result);
	$response->header( 'Content-Length' => length($content) );
	$response->code(200);
	$response->header('Connection' => 'close');
	$response->content_type('application/json');

	Slim::Web::HTTP::addHTTPResponse( $httpClient, $response, \$content );
}

sub startHelper {
	my ($class) = @_;

	# no need to restart if it's already there
	return $helper->alive if $helper && $helper->alive;

	# a helper which keeps dying (eg. no network) would otherwise be restarted on every status poll
	# report success: the helper exists, we're just holding back
	return 1 if time() - $lastStart < RESTART_DELAY;

	if ( my $helperPath = Plugins::Spotty::Helper->get() ) {
		if ( !($helper && $helper->alive) ) {
			$lastStart = time();

			my @helperArgs = (
				'-c', Plugins::Spotty::AccountHelper->playerAuthFolder(),
				'-n', sprintf("%s (%s)", Slim::Utils::Strings::string('PLUGIN_SPOTTY_AUTH_NAME'), Slim::Utils::Misc::getLibraryName()),
				'--authenticate'
			);

			# log in with a code on spotify.com/pair - doesn't depend on mDNS reaching the user's phone
			if (Plugins::Spotty::Helper->getCapability('device-auth')) {
				my $codeFile = $class->deviceAuthFile();
				unlink $codeFile if -f $codeFile;
				push @helperArgs, '--enable-device-auth', '--device-auth-file', $codeFile;
			}

			# always use fallback (if possible), as the user has no way to force this at this point yet if needed
			if (!Plugins::Spotty::Helper->getCapability('no-ap-port')) {
				push @helperArgs, '--ap-port=12321';
			}

			if (main::INFOLOG && $log->is_info) {
				push @helperArgs, '--verbose' if Plugins::Spotty::Helper->getCapability('debug');
				$log->info("Starting Spotty deamon: \n$helperPath " . join(' ', @helperArgs));
			}

			eval {
				$helper = Proc::Background->new(
					{ 'die_upon_destroy' => 1 },
					$helperPath,
					@helperArgs
				);
			};

			Slim::Utils::Timers::killTimers(undef, \&shutdownHelper);
			Slim::Utils::Timers::setTimer(undef, Time::HiRes::time() + HELPER_TIMEOUT, \&shutdownHelper);

			if ($@) {
				$log->warn("Failed to launch the authentication deamon: $@");
			}
		}
	}

	return $helper && $helper->alive;
}

sub shutdownHelper {
	if ($helper && $helper->alive) {
		main::INFOLOG && $log->is_info && $log->info("Quitting authentication daemon");
		$helper->die;
	}

	my $codeFile = __PACKAGE__->deviceAuthFile();
	unlink $codeFile if -f $codeFile;
}

sub deviceAuthFile {
	return catfile(Plugins::Spotty::AccountHelper->playerAuthFolder(), 'device-auth.json');
}

# pairing code written by the helper: { userCode, url, verificationUri } or { error }
sub getDeviceAuth {
	my $codeFile = __PACKAGE__->deviceAuthFile();
	return unless -f $codeFile;

	my $data = eval {
		open(my $fh, '<', $codeFile) or die "$!\n";
		local $/;
		my $content = <$fh>;
		close $fh;
		decode_json($content);
	};

	if ($@) {
		# the helper might be writing the file right now - try again on the next poll
		main::DEBUGLOG && $log->is_debug && $log->debug("Failed to read device auth file: $@");
		return;
	}

	if (ref $data && $data->{error} && $data->{error} ne $lastError) {
		$log->warn("Device authorization failed: $data->{error}");
		$lastError = $data->{error};
	}

	return ref $data eq 'HASH' ? $data : undef;
}


1;