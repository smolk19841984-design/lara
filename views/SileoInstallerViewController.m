//
//  SileoInstallerViewController.m
//  lara
//

#import "SileoInstallerViewController.h"
#import <CoreFoundation/CoreFoundation.h>
#import "../kexploit/sbx.h"
#import "../kexploit/darksword.h"
#import "../kexploit/vfs.h"
#import "../LaraManager.h"
#import "../Logger.h"
#include <sys/stat.h>
#include <spawn.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <dlfcn.h>
#include <zstd.h>

#define POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE 1
extern int posix_spawnattr_set_persona_np(const posix_spawnattr_t * __restrict, uid_t, uint32_t);
extern int posix_spawnattr_set_persona_uid_np(const posix_spawnattr_t * __restrict, uid_t);
extern int posix_spawnattr_set_persona_gid_np(const posix_spawnattr_t * __restrict, uid_t);

static void _sileo_sbx_log(const char *msg) {
    if (!msg) return;
    [[Logger shared] log:[NSString stringWithUTF8String:msg]];
}

static int _sileo_spawn_with_root_persona(pid_t *pid,
                                          const char *cmd,
                                          posix_spawn_file_actions_t *actions,
                                          char *const argv[],
                                          char *const envp[],
                                          NSString **diagOut)
{
    posix_spawnattr_t attr;
    int initRc = posix_spawnattr_init(&attr);
    int personaRc = 0;
    int uidRc = 0;
    int gidRc = 0;
    int spawnRc = EPERM;

    if (initRc == 0) {
        personaRc = posix_spawnattr_set_persona_np(&attr, 99, POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE);
        if (personaRc == 0) {
            uidRc = posix_spawnattr_set_persona_uid_np(&attr, 0);
        }
        if (personaRc == 0 && uidRc == 0) {
            gidRc = posix_spawnattr_set_persona_gid_np(&attr, 0);
        }
        if (personaRc == 0 && uidRc == 0 && gidRc == 0) {
            spawnRc = posix_spawn(pid, cmd, actions, &attr, argv, envp);
        }
        posix_spawnattr_destroy(&attr);
    }

    if (diagOut) {
        *diagOut = [NSString stringWithFormat:@"init=%d persona=%d uid=%d gid=%d spawn=%d",
                    initRc, personaRc, uidRc, gidRc, spawnRc];
    }

    if (initRc != 0) return initRc;
    if (personaRc != 0) return personaRc;
    if (uidRc != 0) return uidRc;
    if (gidRc != 0) return gidRc;
    return spawnRc;
}

// ── Constants ─────────────────────────────────────────────────────────────────

static NSString * const kGitHubAPIURL =
    @"https://api.github.com/repos/Sileo/Sileo/releases/latest";

static NSString * const kSileoRepoURL = @"https://repo.getsileo.app/";
static NSString * const kProcursusBootstrapURLFormat = @"https://apt.procurs.us/bootstraps/%@/bootstrap-ssh-iphoneos-arm64.tar.zst";
static NSString * const kBundledBootstrapName = @"bootstrap-ssh-iphoneos-arm64.tar.zst";
static NSString * const kBootstrapInstalledMarker = @"/.installed_dopamine";
static NSString * const kInstallerRuntimeTag = @"2026-04-09-r22-token-probe-docs-stage";

struct archive;
struct archive_entry;
typedef struct archive _sileo_archive_t;
typedef struct archive_entry _sileo_archive_entry_t;

typedef struct {
    void *handle;
    _sileo_archive_t *(*read_new)(void);
    int (*read_support_filter_all)(_sileo_archive_t *);
    int (*read_support_format_all)(_sileo_archive_t *);
    int (*read_support_format_tar)(_sileo_archive_t *);
    int (*read_open_filename)(_sileo_archive_t *, const char *, size_t);
    int (*read_next_header)(_sileo_archive_t *, _sileo_archive_entry_t **);
    ssize_t (*read_data)(_sileo_archive_t *, void *, size_t);
    int (*read_data_skip)(_sileo_archive_t *);
    int (*read_free)(_sileo_archive_t *);
    const char *(*error_string)(_sileo_archive_t *);
    const char *(*entry_pathname)(_sileo_archive_entry_t *);
    const char *(*entry_symlink)(_sileo_archive_entry_t *);
    const char *(*entry_hardlink)(_sileo_archive_entry_t *);
    mode_t (*entry_mode)(_sileo_archive_entry_t *);
} _sileo_libarchive_api_t;

#define SILEO_ARCHIVE_OK 0
#define SILEO_ARCHIVE_EOF 1

// Diagnostic stage root used only for extraction testing when bootstrap root cannot be created.
static NSString *g_sileo_diagnostic_stage_root = nil;

// Centralized bootstrap root for jailed/userland окружения.
// Исторически это было "/var/jb"; для нашего сценария используем
// пользовательский persistent‑каталог под mobile.
static NSString *lara_bootstrap_root(void) {
    return @"/var/mobile/jb";
}

static NSString *lara_bootstrap_private_root(void) {
    return @"/private/var/mobile/jb";
}

static NSArray<NSString *> *lara_bootstrap_dpkg_status_candidates(void) {
    NSString *jbRoot = lara_bootstrap_root();
    return @[
        [jbRoot stringByAppendingPathComponent:@"var/lib/dpkg/status"],
        [jbRoot stringByAppendingPathComponent:@"Library/dpkg/status"]
    ];
}

static NSString *lara_first_existing_path(NSArray<NSString *> *candidates) {
    NSFileManager *fm = [NSFileManager defaultManager];
    for (NSString *path in candidates) {
        if (path.length && [fm fileExistsAtPath:path]) {
            return path;
        }
    }
    return nil;
}

static NSError *_sileo_bootstrap_error(NSInteger code, NSString *description) {
    return [NSError errorWithDomain:@"SileoInstaller"
                               code:code
                           userInfo:@{NSLocalizedDescriptionKey: description ?: @"unknown error"}];
}

static void _sileo_unload_libarchive(_sileo_libarchive_api_t *api) {
    if (!api) return;
    if (api->handle) {
        dlclose(api->handle);
    }
    memset(api, 0, sizeof(*api));
}

static BOOL _sileo_load_libarchive(_sileo_libarchive_api_t *api, NSString **reason) {
    if (!api) {
        if (reason) *reason = @"libarchive API storage is missing";
        return NO;
    }

    memset(api, 0, sizeof(*api));

    const char *candidates[] = {
        "/usr/lib/libarchive.2.dylib",
        "/usr/lib/libarchive.dylib",
        NULL
    };

    for (int i = 0; candidates[i] != NULL; i++) {
        api->handle = dlopen(candidates[i], RTLD_NOW);
        if (api->handle) {
            break;
        }
    }

    if (!api->handle) {
        if (reason) *reason = @"libarchive runtime is unavailable";
        return NO;
    }

#define SILEO_LOAD_ARCHIVE_SYM(field, symbol) \
    do { \
        *(void **)(&api->field) = dlsym(api->handle, symbol); \
        if (!api->field) { \
            if (reason) *reason = [NSString stringWithFormat:@"missing libarchive symbol %s", symbol]; \
            _sileo_unload_libarchive(api); \
            return NO; \
        } \
    } while (0)

    SILEO_LOAD_ARCHIVE_SYM(read_new, "archive_read_new");
    SILEO_LOAD_ARCHIVE_SYM(read_support_filter_all, "archive_read_support_filter_all");
    *(void **)(&api->read_support_format_all) = dlsym(api->handle, "archive_read_support_format_all");
    *(void **)(&api->read_support_format_tar) = dlsym(api->handle, "archive_read_support_format_tar");
    if (!api->read_support_format_all && !api->read_support_format_tar) {
        if (reason) *reason = @"libarchive does not expose a readable tar format loader";
        _sileo_unload_libarchive(api);
        return NO;
    }
    SILEO_LOAD_ARCHIVE_SYM(read_open_filename, "archive_read_open_filename");
    SILEO_LOAD_ARCHIVE_SYM(read_next_header, "archive_read_next_header");
    SILEO_LOAD_ARCHIVE_SYM(read_data, "archive_read_data");
    *(void **)(&api->read_data_skip) = dlsym(api->handle, "archive_read_data_skip");
    SILEO_LOAD_ARCHIVE_SYM(read_free, "archive_read_free");
    SILEO_LOAD_ARCHIVE_SYM(error_string, "archive_error_string");
    SILEO_LOAD_ARCHIVE_SYM(entry_pathname, "archive_entry_pathname");
    *(void **)(&api->entry_symlink) = dlsym(api->handle, "archive_entry_symlink");
    *(void **)(&api->entry_hardlink) = dlsym(api->handle, "archive_entry_hardlink");
    SILEO_LOAD_ARCHIVE_SYM(entry_mode, "archive_entry_mode");

#undef SILEO_LOAD_ARCHIVE_SYM

    return YES;
}

static BOOL _sileo_is_bootstrap_regular_file(mode_t mode) {
    return S_ISREG(mode) || ((mode & S_IFMT) == 0);
}

static NSString *_sileo_normalize_archive_entry_target(NSString *rawPath,
                                                       NSString *destinationRoot,
                                                       BOOL *optionalOut) {
    if (optionalOut) *optionalOut = NO;
    if (!rawPath.length || !destinationRoot.length) return nil;

    NSString *normalized = [rawPath stringByReplacingOccurrencesOfString:@"\\" withString:@"/"];
    while ([normalized hasPrefix:@"./"]) {
        normalized = [normalized substringFromIndex:2];
    }
    while ([normalized hasPrefix:@"/"]) {
        normalized = [normalized substringFromIndex:1];
    }

    if (!normalized.length) return nil;

    NSArray<NSString *> *parts = [normalized pathComponents];
    NSMutableArray<NSString *> *clean = [NSMutableArray arrayWithCapacity:parts.count];
    for (NSString *part in parts) {
        if (!part.length || [part isEqualToString:@"/"] || [part isEqualToString:@"."]) {
            continue;
        }
        if ([part isEqualToString:@".."] || [part containsString:@":"]) {
            return nil;
        }
        [clean addObject:part];
    }

    if (clean.count == 0) return nil;

    NSString *relative = [NSString pathWithComponents:clean];
    NSString *privatePrefix = @"private/var/mobile/jb";
    if ([relative isEqualToString:privatePrefix] || [relative hasPrefix:[privatePrefix stringByAppendingString:@"/"]]) {
        relative = [@"var/jb" stringByAppendingString:[relative substringFromIndex:privatePrefix.length]];
        while ([relative hasPrefix:@"var/jb//"]) {
            relative = [@"var/jb/" stringByAppendingString:[relative substringFromIndex:8]];
        }
    }

    if ([relative isEqualToString:@".installed_dopamine"]) {
        if (optionalOut) *optionalOut = YES;
        return [destinationRoot isEqualToString:@"/"]
            ? @"/.installed_dopamine"
            : [destinationRoot stringByAppendingPathComponent:@".installed_dopamine"];
    }

    if (![relative isEqualToString:@"var/jb"] && ![relative hasPrefix:@"var/jb/"]) {
        return nil;
    }

    if ([destinationRoot isEqualToString:@"/"]) {
        // Если есть diagnostic stage-root, перенаправляем туда.
        if (g_sileo_diagnostic_stage_root && [relative hasPrefix:@"var/jb"]) {
            return [g_sileo_diagnostic_stage_root stringByAppendingPathComponent:relative];
        }

        // По умолчанию payload, адресованный в tar как var/jb/..., перекладываем
        // в наше userland‑корневое дерево под lara_bootstrap_root().
        NSString *jbRoot = lara_bootstrap_root();
        if ([relative isEqualToString:@"var/jb"]) {
            return jbRoot;
        }

        NSString *suffix = [relative substringFromIndex:strlen("var/jb")];
        while ([suffix hasPrefix:@"/"]) {
            suffix = [suffix substringFromIndex:1];
        }
        if (!suffix.length) {
            return jbRoot;
        }
        return [jbRoot stringByAppendingPathComponent:suffix];
    }
    return [destinationRoot stringByAppendingPathComponent:relative];
}

static BOOL _sileo_is_extraction_command(NSArray<NSString *> *args) {
    if (args.count == 0) return NO;
    NSString *joined = [[args componentsJoinedByString:@" "] lowercaseString];
    return [joined containsString:@" tar"] ||
           [joined containsString:@"/tar"] ||
           [joined containsString:@"bsdtar"] ||
           [joined containsString:@"zstd"] ||
           [joined containsString:@"prep_bootstrap.sh"] ||
           [joined containsString:@" -xf "] ||
           [joined containsString:@"--use-compress-program"] ||
           [joined containsString:@" -i "];
}

static BOOL _sileo_should_try_root_persona_fallback(const char *cmd,
                                                    NSArray<NSString *> *args)
{
    if (!cmd || getuid() == 0) return NO;
    if (_sileo_is_extraction_command(args)) return YES;

    NSString *command = [NSString stringWithUTF8String:cmd] ?: @"";
    NSString *lowerCommand = [command lowercaseString];
    NSString *joined = [[args componentsJoinedByString:@" "] lowercaseString];

    return [lowerCommand hasSuffix:@"/apt"] ||
           [lowerCommand hasSuffix:@"/apt-get"] ||
           [lowerCommand hasSuffix:@"/apt-cache"] ||
           [lowerCommand hasSuffix:@"/dpkg"] ||
            [lowerCommand hasSuffix:@"/mkdir"] ||
            [lowerCommand hasSuffix:@"/chmod"] ||
            [lowerCommand hasSuffix:@"/chown"] ||
           [lowerCommand hasSuffix:@"/bash"] ||
           [lowerCommand hasSuffix:@"/sh"] ||
           [joined containsString:@"prep_bootstrap.sh"] ||
           [joined containsString:@"apt-get"] ||
           [joined containsString:@"apt "] ||
           [joined containsString:@"dpkg "] ||
            [joined containsString:@"mkdir "] ||
            [joined containsString:@"chmod "] ||
            [joined containsString:@"chown "] ||
           [joined containsString:@"/var/mobile/jb/"];
}

// ── UI state machine ──────────────────────────────────────────────────────────

typedef NS_ENUM(NSInteger, InstallerState) {
    InstallerStateIdle = 0,
    InstallerStateFetching,     // fetching release metadata
    InstallerStateInstalling,   // installing dependencies + sileo via apt
    InstallerStateDone,
    InstallerStateError
};

// ── Package info row ──────────────────────────────────────────────────────────

typedef struct { NSString *name; NSString *desc; NSString *icon; } PkgInfo;
static PkgInfo kPackages[] = {
    { @"Sileo",       @"Modern package manager for jailbroken iOS",   @"bag.fill"                },
    { @"Procursus",   @"Rootless bootstrap and package dependencies",  @"shippingbox.fill"        },
    { @"APT stack",   @"apt/dpkg components required by Sileo",       @"terminal.fill"           },
};
static const NSInteger kPackageCount = 3;

// ─────────────────────────────────────────────────────────────────────────────
@interface SileoInstallerViewController ()

// UI
@property (nonatomic, strong) UIScrollView       *scrollView;
@property (nonatomic, strong) UIView             *contentView;
@property (nonatomic, strong) UIImageView        *iconView;
@property (nonatomic, strong) UILabel            *titleLabel;
@property (nonatomic, strong) UILabel            *subtitleLabel;
@property (nonatomic, strong) UITableView        *packageTable;
@property (nonatomic, strong) UIButton           *installButton;
@property (nonatomic, strong) UIProgressView     *progressBar;
@property (nonatomic, strong) UILabel            *statusLabel;
@property (nonatomic, strong) UILabel            *versionLabel;
@property (nonatomic, strong) UITextView         *logView;

// State
@property (nonatomic, assign) InstallerState state;
@property (nonatomic, strong) NSString       *latestVersion;
@property (nonatomic, strong) NSMutableString *commandLog;
@property (nonatomic, strong) NSString       *logFilePath;

- (NSString *)bundledHelperExecutable:(NSString *)name;
- (NSString *)bundledBootstrapArchivePath;
- (NSString *)bootstrapHelperExecutableForNames:(NSArray<NSString *> *)names;
- (NSString *)bootstrapShellExecutable;
- (BOOL)ensureBootstrapRootDirectoryWithReason:(NSString **)reason;
- (NSString *)stageHelperToJBTools:(NSString *)name;
- (BOOL)isInProcessBootstrapExtractorAvailableWithReason:(NSString **)reason;
- (BOOL)extractBootstrapArchiveInProcessAtPath:(NSString *)archivePath destination:(NSString *)destination error:(NSError **)err;
- (void)fixBootstrapPermissionsForRootless;
- (void)prepareSandboxExtensionsForBootstrapPaths:(NSArray<NSString *> *)paths;
- (BOOL)canBootstrapInCurrentContext:(NSString **)reason;
- (void)appendInstallEnvironmentSnapshot;
- (BOOL)verifyInstallPrerequisitesWithError:(NSError **)err aptPath:(NSString *)aptGet;
- (BOOL)verifySileoInstallationWithError:(NSError **)err;
- (NSTimeInterval)timeoutForCommandArgs:(NSArray<NSString *> *)args;

@end

// VFS-backed mkdir with chown fallback for rootless (uid=501) operation
static BOOL _sileo_ensure_directory(NSString *path, NSError **outErr) {
    NSFileManager *fm = [NSFileManager defaultManager];
    if ([fm fileExistsAtPath:path]) return YES;

    NSError *err = nil;
    if ([fm createDirectoryAtPath:path withIntermediateDirectories:YES attributes:nil error:&err]) {
        return YES;
    }

    // Normal mkdir failed — try VFS chown + mkdir
    if (vfs_isready() && vfs_mkdir_p(path.fileSystemRepresentation, 501, 501) == 0) {
        return YES;
    }

    if (outErr) *outErr = err;
    return NO;
}

@implementation SileoInstallerViewController

// ── Lifecycle ─────────────────────────────────────────────────────────────────

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"Sileo Installer";
    self.view.backgroundColor = UIColor.systemGroupedBackgroundColor;

    [self buildLayout];
    [self preparePersistentLogFile];
    [self fetchLatestVersion];
}

// ── Layout ────────────────────────────────────────────────────────────────────

- (void)buildLayout {
    // Scroll container
    self.scrollView = [[UIScrollView alloc] init];
    self.scrollView.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:self.scrollView];

    self.contentView = [[UIView alloc] init];
    self.contentView.translatesAutoresizingMaskIntoConstraints = NO;
    [self.scrollView addSubview:self.contentView];

    UILayoutGuide *safeArea = self.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
        [self.scrollView.topAnchor      constraintEqualToAnchor:safeArea.topAnchor],
        [self.scrollView.leadingAnchor  constraintEqualToAnchor:self.view.leadingAnchor],
        [self.scrollView.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor],
        [self.scrollView.bottomAnchor   constraintEqualToAnchor:self.view.bottomAnchor],

        [self.contentView.topAnchor     constraintEqualToAnchor:self.scrollView.topAnchor],
        [self.contentView.leadingAnchor constraintEqualToAnchor:self.scrollView.leadingAnchor],
        [self.contentView.trailingAnchor constraintEqualToAnchor:self.scrollView.trailingAnchor],
        [self.contentView.bottomAnchor  constraintEqualToAnchor:self.scrollView.bottomAnchor],
        [self.contentView.widthAnchor   constraintEqualToAnchor:self.scrollView.widthAnchor],
    ]];

    // App icon
    self.iconView = [[UIImageView alloc] init];
    self.iconView.translatesAutoresizingMaskIntoConstraints = NO;
    self.iconView.layer.cornerRadius = 22;
    self.iconView.layer.masksToBounds = YES;
    self.iconView.backgroundColor = UIColor.systemIndigoColor;
    self.iconView.contentMode = UIViewContentModeCenter;
    UIImage *sileo = [UIImage systemImageNamed:@"bag.fill"
                     withConfiguration:[UIImageSymbolConfiguration configurationWithPointSize:44
                                                                                       weight:UIImageSymbolWeightMedium]];
    self.iconView.image = [sileo imageWithTintColor:UIColor.whiteColor
                                      renderingMode:UIImageRenderingModeAlwaysOriginal];
    [self.contentView addSubview:self.iconView];

    // Title
    self.titleLabel = [[UILabel alloc] init];
    self.titleLabel.translatesAutoresizingMaskIntoConstraints = NO;
    self.titleLabel.text = @"Sileo & Dependencies";
    self.titleLabel.font = [UIFont systemFontOfSize:26 weight:UIFontWeightBold];
    self.titleLabel.textColor = UIColor.labelColor;
    self.titleLabel.textAlignment = NSTextAlignmentCenter;
    [self.contentView addSubview:self.titleLabel];

    // Version label
    self.versionLabel = [[UILabel alloc] init];
    self.versionLabel.translatesAutoresizingMaskIntoConstraints = NO;
    self.versionLabel.text = @"Fetching latest version...";
    self.versionLabel.font = [UIFont systemFontOfSize:14];
    self.versionLabel.textColor = UIColor.secondaryLabelColor;
    self.versionLabel.textAlignment = NSTextAlignmentCenter;
    [self.contentView addSubview:self.versionLabel];

    // Subtitle
    self.subtitleLabel = [[UILabel alloc] init];
    self.subtitleLabel.translatesAutoresizingMaskIntoConstraints = NO;
    self.subtitleLabel.text = @"Installs Sileo package manager and essential packages "
                               @"needed to manage your jailbreak.";
    self.subtitleLabel.font = [UIFont systemFontOfSize:15];
    self.subtitleLabel.textColor = UIColor.secondaryLabelColor;
    self.subtitleLabel.numberOfLines = 0;
    self.subtitleLabel.textAlignment = NSTextAlignmentCenter;
    [self.contentView addSubview:self.subtitleLabel];

    // Package list (static UITableView)
    self.packageTable = [[UITableView alloc] initWithFrame:CGRectZero
                                                     style:UITableViewStyleInsetGrouped];
    self.packageTable.translatesAutoresizingMaskIntoConstraints = NO;
    self.packageTable.dataSource = (id<UITableViewDataSource>)self;
    self.packageTable.delegate   = (id<UITableViewDelegate>)self;
    self.packageTable.scrollEnabled = NO;
    self.packageTable.userInteractionEnabled = NO;
    [self.contentView addSubview:self.packageTable];

    CGFloat tableH = (CGFloat)kPackageCount * 60.0 + 60.0;
    [self.packageTable.heightAnchor constraintEqualToConstant:tableH].active = YES;

    // Progress bar (hidden initially)
    self.progressBar = [[UIProgressView alloc] initWithProgressViewStyle:UIProgressViewStyleDefault];
    self.progressBar.translatesAutoresizingMaskIntoConstraints = NO;
    self.progressBar.alpha = 0;
    self.progressBar.tintColor = UIColor.systemIndigoColor;
    [self.contentView addSubview:self.progressBar];

    // Status label
    self.statusLabel = [[UILabel alloc] init];
    self.statusLabel.translatesAutoresizingMaskIntoConstraints = NO;
    self.statusLabel.text = @"";
    self.statusLabel.font = [UIFont monospacedSystemFontOfSize:12 weight:UIFontWeightRegular];
    self.statusLabel.textColor = UIColor.secondaryLabelColor;
    self.statusLabel.numberOfLines = 0;
    self.statusLabel.textAlignment = NSTextAlignmentCenter;
    [self.contentView addSubview:self.statusLabel];

    // Full command log (apt output)
    self.logView = [[UITextView alloc] init];
    self.logView.translatesAutoresizingMaskIntoConstraints = NO;
    self.logView.font = [UIFont monospacedSystemFontOfSize:11 weight:UIFontWeightRegular];
    self.logView.textColor = UIColor.secondaryLabelColor;
    self.logView.backgroundColor = [UIColor secondarySystemGroupedBackgroundColor];
    self.logView.layer.cornerRadius = 10;
    self.logView.editable = NO;
    self.logView.selectable = YES;
    self.logView.scrollEnabled = YES;
    self.logView.text = @"";
    [self.contentView addSubview:self.logView];

    // Install button
    self.installButton = [UIButton buttonWithType:UIButtonTypeSystem];
    self.installButton.translatesAutoresizingMaskIntoConstraints = NO;
    [self.installButton setTitle:@"Install" forState:UIControlStateNormal];
    self.installButton.titleLabel.font = [UIFont systemFontOfSize:18 weight:UIFontWeightSemibold];
    self.installButton.backgroundColor = UIColor.systemIndigoColor;
    [self.installButton setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
    self.installButton.layer.cornerRadius = 14;
    self.installButton.layer.masksToBounds = YES;
    [self.installButton addTarget:self
                           action:@selector(installTapped)
                 forControlEvents:UIControlEventTouchUpInside];
    [self.contentView addSubview:self.installButton];

    CGFloat margin = 24;
    [NSLayoutConstraint activateConstraints:@[
        // Icon
        [self.iconView.topAnchor       constraintEqualToAnchor:self.contentView.topAnchor constant:32],
        [self.iconView.centerXAnchor   constraintEqualToAnchor:self.contentView.centerXAnchor],
        [self.iconView.widthAnchor     constraintEqualToConstant:100],
        [self.iconView.heightAnchor    constraintEqualToConstant:100],

        // Title
        [self.titleLabel.topAnchor     constraintEqualToAnchor:self.iconView.bottomAnchor constant:16],
        [self.titleLabel.leadingAnchor constraintEqualToAnchor:self.contentView.leadingAnchor constant:margin],
        [self.titleLabel.trailingAnchor constraintEqualToAnchor:self.contentView.trailingAnchor constant:-margin],

        // Version
        [self.versionLabel.topAnchor   constraintEqualToAnchor:self.titleLabel.bottomAnchor constant:4],
        [self.versionLabel.leadingAnchor constraintEqualToAnchor:self.contentView.leadingAnchor constant:margin],
        [self.versionLabel.trailingAnchor constraintEqualToAnchor:self.contentView.trailingAnchor constant:-margin],

        // Subtitle
        [self.subtitleLabel.topAnchor  constraintEqualToAnchor:self.versionLabel.bottomAnchor constant:12],
        [self.subtitleLabel.leadingAnchor constraintEqualToAnchor:self.contentView.leadingAnchor constant:margin],
        [self.subtitleLabel.trailingAnchor constraintEqualToAnchor:self.contentView.trailingAnchor constant:-margin],

        // Table
        [self.packageTable.topAnchor   constraintEqualToAnchor:self.subtitleLabel.bottomAnchor constant:20],
        [self.packageTable.leadingAnchor constraintEqualToAnchor:self.contentView.leadingAnchor],
        [self.packageTable.trailingAnchor constraintEqualToAnchor:self.contentView.trailingAnchor],

        // Progress
        [self.progressBar.topAnchor    constraintEqualToAnchor:self.packageTable.bottomAnchor constant:20],
        [self.progressBar.leadingAnchor constraintEqualToAnchor:self.contentView.leadingAnchor constant:margin],
        [self.progressBar.trailingAnchor constraintEqualToAnchor:self.contentView.trailingAnchor constant:-margin],

        // Status
        [self.statusLabel.topAnchor    constraintEqualToAnchor:self.progressBar.bottomAnchor constant:8],
        [self.statusLabel.leadingAnchor constraintEqualToAnchor:self.contentView.leadingAnchor constant:margin],
        [self.statusLabel.trailingAnchor constraintEqualToAnchor:self.contentView.trailingAnchor constant:-margin],

        // Log
        [self.logView.topAnchor        constraintEqualToAnchor:self.statusLabel.bottomAnchor constant:10],
        [self.logView.leadingAnchor    constraintEqualToAnchor:self.contentView.leadingAnchor constant:margin],
        [self.logView.trailingAnchor   constraintEqualToAnchor:self.contentView.trailingAnchor constant:-margin],
        [self.logView.heightAnchor     constraintEqualToConstant:170],

        // Button
        [self.installButton.topAnchor  constraintEqualToAnchor:self.logView.bottomAnchor constant:20],
        [self.installButton.leadingAnchor constraintEqualToAnchor:self.contentView.leadingAnchor constant:margin],
        [self.installButton.trailingAnchor constraintEqualToAnchor:self.contentView.trailingAnchor constant:-margin],
        [self.installButton.heightAnchor constraintEqualToConstant:54],
        [self.installButton.bottomAnchor constraintEqualToAnchor:self.contentView.bottomAnchor constant:-40],
    ]];
}

// ── UITableView (package list) ────────────────────────────────────────────────

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tv { return 1; }

- (NSInteger)tableView:(UITableView *)tv numberOfRowsInSection:(NSInteger)sec {
    return kPackageCount;
}

- (NSString *)tableView:(UITableView *)tv titleForHeaderInSection:(NSInteger)sec {
    return @"What will be installed";
}

- (UITableViewCell *)tableView:(UITableView *)tv cellForRowAtIndexPath:(NSIndexPath *)ip {
    UITableViewCell *cell = [tv dequeueReusableCellWithIdentifier:@"pkg"];
    if (!cell) {
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle
                                      reuseIdentifier:@"pkg"];
    }
    PkgInfo p = kPackages[ip.row];
    cell.textLabel.text = p.name;
    cell.detailTextLabel.text = p.desc;
    cell.detailTextLabel.textColor = UIColor.secondaryLabelColor;
    UIImage *img = [UIImage systemImageNamed:p.icon];
    cell.imageView.image = [img imageWithTintColor:UIColor.systemIndigoColor
                                     renderingMode:UIImageRenderingModeAlwaysOriginal];
    cell.selectionStyle = UITableViewCellSelectionStyleNone;
    return cell;
}

// ── Networking ────────────────────────────────────────────────────────────────

- (void)fetchLatestVersion {
    NSURL *apiURL = [NSURL URLWithString:kGitHubAPIURL];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:apiURL];
    req.timeoutInterval = 10.0;
    [req setValue:@"application/vnd.github+json" forHTTPHeaderField:@"Accept"];
    [req setValue:@"lara-jailbreak/1.0" forHTTPHeaderField:@"User-Agent"];

    [[[NSURLSession sharedSession] dataTaskWithRequest:req
                                     completionHandler:^(NSData *data, NSURLResponse *r, NSError *err) {
        dispatch_async(dispatch_get_main_queue(), ^{
            if (err || !data) {
                [self appendCommandLog:[NSString stringWithFormat:@"[fetch] latest version unavailable: %@\n", err.localizedDescription ?: @"no data"]];
                self.versionLabel.text = @"Version unavailable";
                return;
            }
            NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
            NSString *tag = json[@"tag_name"] ?: @"";
            self.latestVersion = tag;
            self.versionLabel.text = tag.length ? [NSString stringWithFormat:@"Latest: %@", tag]
                                                : @"Version unknown";
        });
    }] resume];
}

- (void)installTapped {
    if (self.state != InstallerStateIdle && self.state != InstallerStateError &&
        self.state != InstallerStateDone) {
        [self appendCommandLog:[NSString stringWithFormat:@"[install] request ignored in state=%ld\n", (long)self.state]];
        return;
    }

    [self resetCommandLog];
    [self setState:InstallerStateFetching status:@"Running preflight…"];

    NSString *preflight = [self preflightErrorMessage];
    if (preflight) {
        [self appendCommandLog:[NSString stringWithFormat:@"[preflight] %@\n", preflight]];
        [self setState:InstallerStateError status:preflight];
        return;
    }

    [self setState:InstallerStateFetching status:@"Preparing installer pipeline…"];
    [self appendCommandLog:@"[install] pipeline: preflight -> bootstrap -> core repo -> pre-apt verify -> apt update -> apt install -> package verify -> optional sources -> uicache\n"];
    NSString *status = self.latestVersion.length ? [NSString stringWithFormat:@"Installing Sileo %@…", self.latestVersion] : @"Installing Sileo…";
    [self installViaAptWithStatus:status];
}

- (void)installViaAptWithStatus:(NSString *)status {
    [self setState:InstallerStateInstalling status:status];
    [self setProgress:0.02 status:@"Collecting install environment…"];

    __weak typeof(self) weak = self;
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        if (!weak) return;
        [weak appendInstallEnvironmentSnapshot];

        dispatch_async(dispatch_get_main_queue(), ^{
            if (!weak) return;
            [weak setProgress:0.05 status:@"Checking bootstrap…"];
        });

        NSError *bootstrapErr = nil;
        if (![weak ensureBootstrapInstalledIfNeeded:&bootstrapErr]) {
            [weak appendCommandLog:[NSString stringWithFormat:@"[bootstrap] error: %@\n", bootstrapErr.localizedDescription ?: @"unknown"]];
            dispatch_async(dispatch_get_main_queue(), ^{
                if (!weak) return;
                [weak setState:InstallerStateError status:[NSString stringWithFormat:@"Bootstrap failed: %@", bootstrapErr.localizedDescription]];
            });
            return;
        }

        dispatch_async(dispatch_get_main_queue(), ^{
            if (!weak) return;
            [weak setProgress:0.20 status:@"Configuring repositories…"];
        });

        NSError *sourcesErr = nil;
        if (![weak ensureDefaultSourcesConfigured:&sourcesErr]) {
            [weak appendCommandLog:[NSString stringWithFormat:@"[sources] error: %@\n", sourcesErr.localizedDescription ?: @"unknown"]];
            dispatch_async(dispatch_get_main_queue(), ^{
                if (!weak) return;
                [weak setState:InstallerStateError status:[NSString stringWithFormat:@"Sources setup failed: %@", sourcesErr.localizedDescription]];
            });
            return;
        }

        NSError *repoErr = nil;
        if (![weak ensureSileoRepoConfigured:&repoErr]) {
            [weak appendCommandLog:[NSString stringWithFormat:@"[repo] error: %@\n", repoErr.localizedDescription ?: @"unknown"]];
            dispatch_async(dispatch_get_main_queue(), ^{
                if (!weak) return;
                [weak setState:InstallerStateError status:[NSString stringWithFormat:@"Repo setup failed: %@", repoErr.localizedDescription]];
            });
            return;
        }
        [weak appendCommandLog:@"[repo] configured getsileo source\n"];

        dispatch_async(dispatch_get_main_queue(), ^{
            if (!weak) return;
            [weak setProgress:0.35 status:@"Running apt update…"];
        });
        NSString *aptGet = [weak firstExistingExecutable:@[@"/var/mobile/jb/usr/bin/apt-get", @"/usr/bin/apt-get"]];
        if (!aptGet) {
            [weak appendCommandLog:@"[apt] apt-get not found in /var/mobile/jb/usr/bin or /usr/bin\n"];
            [weak appendCommandLog:[weak aptBinaryDiagnostics]];
            dispatch_async(dispatch_get_main_queue(), ^{
                if (!weak) return;
                [weak setState:InstallerStateError status:@"apt-get not found. Run bootstrap first."];
            });
            return;
        }

        NSError *preAptErr = nil;
        if (![weak verifyInstallPrerequisitesWithError:&preAptErr aptPath:aptGet]) {
            [weak appendCommandLog:[NSString stringWithFormat:@"[verify:pre-apt] error: %@\n", preAptErr.localizedDescription ?: @"unknown"]];
            dispatch_async(dispatch_get_main_queue(), ^{
                if (!weak) return;
                [weak setState:InstallerStateError status:[NSString stringWithFormat:@"Pre-apt verification failed: %@", preAptErr.localizedDescription]];
            });
            return;
        }

        NSString *aptUpdateOut = nil;
        int rc = [weak runCommand:@[aptGet, @"update"] output:&aptUpdateOut];
        [weak appendCommandOutputForCommand:[NSString stringWithFormat:@"%@ update", aptGet] output:aptUpdateOut exitCode:rc];
        if (rc != 0) {
            [weak appendCommandLog:[NSString stringWithFormat:@"[apt] update failed with rc=%d\n", rc]];
            dispatch_async(dispatch_get_main_queue(), ^{
                if (!weak) return;
                [weak setState:InstallerStateError
                        status:[NSString stringWithFormat:@"apt update failed (%d). Full log below.", rc]];
            });
            return;
        }
        NSString *installOut = nil;
        rc = [weak runCommand:@[aptGet, @"install", @"-y", @"org.coolstar.sileo"] output:&installOut];
        [weak appendCommandOutputForCommand:[NSString stringWithFormat:@"%@ install -y org.coolstar.sileo", aptGet] output:installOut exitCode:rc];
        if (rc != 0) {
            [weak appendCommandLog:[NSString stringWithFormat:@"[apt] install failed with rc=%d\n", rc]];
            dispatch_async(dispatch_get_main_queue(), ^{
                if (!weak) return;
                [weak setState:InstallerStateError
                        status:[NSString stringWithFormat:@"apt install failed (%d). Full log below.", rc]];
            });
            return;
        }

        dispatch_async(dispatch_get_main_queue(), ^{
            if (!weak) return;
            [weak setProgress:0.82 status:@"Verifying installed package…"];
        });

        NSError *packageErr = nil;
        if (![weak verifySileoInstallationWithError:&packageErr]) {
            [weak appendCommandLog:[NSString stringWithFormat:@"[verify:post-apt] error: %@\n", packageErr.localizedDescription ?: @"unknown"]];
            dispatch_async(dispatch_get_main_queue(), ^{
                if (!weak) return;
                [weak setState:InstallerStateError status:[NSString stringWithFormat:@"Sileo verification failed: %@", packageErr.localizedDescription]];
            });
            return;
        }

        NSError *postSourcesErr = nil;
        if (![weak ensureDefaultSourcesConfigured:&postSourcesErr]) {
            [weak appendCommandLog:[NSString stringWithFormat:@"[sources] optional sources skipped: %@\n", postSourcesErr.localizedDescription ?: @"unknown"]];
        }

        dispatch_async(dispatch_get_main_queue(), ^{
            if (!weak) return;
            [weak setProgress:0.90 status:@"Refreshing app registrations…"];
        });
        NSString *uicache = [weak firstExistingExecutable:@[@"/var/mobile/jb/usr/bin/uicache", @"/usr/bin/uicache"]];
        if (uicache) {
            NSString *uicacheOut = nil;
            int uiRc = [weak runCommand:@[uicache, @"-a"] output:&uicacheOut];
            [weak appendCommandOutputForCommand:[NSString stringWithFormat:@"%@ -a", uicache] output:uicacheOut exitCode:uiRc];
            if (uiRc != 0) {
                [weak appendCommandLog:[NSString stringWithFormat:@"[uicache] warning: refresh failed with rc=%d\n", uiRc]];
            }
        } else {
            [weak appendCommandLog:@"[uicache] warning: binary not found, Sileo may require manual respring or app registration refresh\n"];
        }

        dispatch_async(dispatch_get_main_queue(), ^{
            if (!weak) return;
            [weak setProgress:1.0 status:@"✓ Sileo installed via apt (with dependencies)."];
            [weak setState:InstallerStateDone
                    status:@"✓ Sileo installed via apt (with dependencies).\n\nRespring to see Sileo on your Home Screen."];
            [weak.installButton setTitle:@"Done" forState:UIControlStateNormal];
            weak.installButton.backgroundColor = UIColor.systemGreenColor;
            [weak offerRespring];
        });
    });
}

- (NSString *)preflightErrorMessage {
    LaraManager *mgr = [LaraManager shared];
    uid_t uid = getuid();
    NSString *selectedMethod = [[NSUserDefaults standardUserDefaults] stringForKey:@"selectedmethod"] ?: @"sbx";
    BOOL wantsSBX = ([selectedMethod caseInsensitiveCompare:@"sbx"] == NSOrderedSame ||
                     [selectedMethod caseInsensitiveCompare:@"hybrid"] == NSOrderedSame);
    BOOL wantsVFS = ([selectedMethod caseInsensitiveCompare:@"vfs"] == NSOrderedSame ||
                     [selectedMethod caseInsensitiveCompare:@"hybrid"] == NSOrderedSame);
    
    if (!vfs_isready()) {
        [self appendCommandLog:@"[preflight] Auto-initializing VFS...\n"];
        vfs_init();
    }
    
    BOOL vfsReady = vfs_isready();

    [self appendCommandLog:[NSString stringWithFormat:@"[preflight] method=%@ ds_ready=%d sbx_ready=%d vfs_ready=%d uid=%d\n",
                            selectedMethod,
                            (int)mgr.dsReady,
                            (int)mgr.sbxReady,
                            (int)vfsReady,
                            uid]];
    if (!mgr.dsReady && uid != 0) {
        return @"Kernel R/W не готов. Установка Sileo блокируется до успешного Run Exploit.";
    }
    if (wantsVFS && !vfsReady) {
        return @"Выбран режим VFS/Hybrid, но VFS не инициализирован (vfs_isready=0). Сначала нажми VFS init.";
    }
    if (wantsSBX && uid != 0 && !mgr.sbxReady) {
        [self appendCommandLog:@"[preflight] sbx not marked ready yet; installer will attempt on-demand sbx_escape/sbx_elevate\n"];
    }

    if (uid != 0) {
        uint64_t ourProc = ds_get_our_proc();
        if (!ourProc) {
            return @"Эксплойт не запущен (ourProc=0). Сначала нажми Run Exploit, затем повтори.";
        }

        sbx_setlogcallback(_sileo_sbx_log);
        [self appendCommandLog:@"[preflight] sbx log callback installed\n"];
        [self appendCommandLog:[NSString stringWithFormat:@"[preflight] uid=%d, trying sbx_escape...\n", uid]];
        int esc = sbx_escape(ourProc);
        [self appendCommandLog:[NSString stringWithFormat:@"[preflight] sbx_escape rc=%d\n", esc]];

        NSString *postEscapeAptReason = nil;
        if ([self canRunAptInCurrentContext:&postEscapeAptReason]) {
            [self appendCommandLog:@"[preflight] post-sbx_escape rootless apt probe passed; skipping sbx_elevate\n"];
            return nil;
        }

        if (vfs_isready() && ![[NSFileManager defaultManager] fileExistsAtPath:@"/var/mobile/jb"]) {
            [self appendCommandLog:@"[preflight] post-sbx_escape creating /var/mobile/jb via VFS before elevate...\n"];
            int mkrc = vfs_mkdir_p("/var/mobile/jb", 501, 501);
            [self appendCommandLog:[NSString stringWithFormat:@"[preflight] post-sbx_escape vfs_mkdir_p /var/mobile/jb rc=%d exists=%d\n",
                                    mkrc, [[NSFileManager defaultManager] fileExistsAtPath:@"/var/mobile/jb"]]];
        }

        NSString *postEscapeBootstrapReason = nil;
        if ([self canBootstrapInCurrentContext:&postEscapeBootstrapReason]) {
            [self appendCommandLog:@"[preflight] post-sbx_escape bootstrap probe passed; skipping sbx_elevate\n"];
            return nil;
        }

        [self appendCommandLog:@"[preflight] post-sbx_escape probes still incomplete; trying sbx_elevate...\n"];

        [self appendCommandLog:[NSString stringWithFormat:@"[preflight] uid=%d, trying sbx_elevate...\n", getuid()]];
        int er = sbx_elevate();
        uid_t uidAfter = getuid();
        [self appendCommandLog:[NSString stringWithFormat:@"[preflight] sbx_elevate rc=%d, uid=%d\n", er, uidAfter]];
        if (uidAfter != 0) {
            if (er != 0) {
                [self appendCommandLog:[NSString stringWithFormat:@"[preflight] sbx_elevate failed (rc=%d), probing rootless execution path before continuing\n", er]];

                NSString *aptReason = nil;
                if ([self canRunAptInCurrentContext:&aptReason]) {
                    [self appendCommandLog:@"[preflight] rootless capability probe passed, continuing without uid=0\n"];
                    return nil;
                }
                [self appendCommandLog:[NSString stringWithFormat:@"[preflight] apt probe failed: %@\n", aptReason ?: @"unknown"]];

                // Ensure /var/mobile/jb exists before probing bootstrap — VFS mkdir
                // temporarily chowns parent dirs and restores them.
                if (vfs_isready() && ![[NSFileManager defaultManager] fileExistsAtPath:@"/var/mobile/jb"]) {
                    [self appendCommandLog:@"[preflight] creating /var/mobile/jb via VFS...\n"];
                    int mkrc = vfs_mkdir_p("/var/mobile/jb", 501, 501);
                    [self appendCommandLog:[NSString stringWithFormat:@"[preflight] vfs_mkdir_p /var/mobile/jb rc=%d exists=%d\n",
                                            mkrc, [[NSFileManager defaultManager] fileExistsAtPath:@"/var/mobile/jb"]]];
                }

                NSString *bootstrapReason = nil;
                if ([self canBootstrapInCurrentContext:&bootstrapReason]) {
                    [self appendCommandLog:@"[preflight] bootstrap capability probe passed, continuing without uid=0\n"];
                    return nil;
                }

                return [NSString stringWithFormat:@"Не удалось получить root (uid=0), apt ещё не готов, и bootstrap не может стартовать в текущем контексте: %@", bootstrapReason ?: aptReason ?: @"unknown"];
            }
            [self appendCommandLog:@"[preflight] uid is still non-root, probing rootless apt capabilities...\n"];
            NSString *reason = nil;
            if ([self canRunAptInCurrentContext:&reason]) {
                [self appendCommandLog:@"[preflight] rootless capability probe passed, continuing without uid=0\n"];
                return nil;
            }

            // apt not available — try bootstrap path with VFS mkdir
            if (vfs_isready() && ![[NSFileManager defaultManager] fileExistsAtPath:@"/var/mobile/jb"]) {
                [self appendCommandLog:@"[preflight] creating /var/mobile/jb via VFS (fallback)...\n"];
                vfs_mkdir_p("/var/mobile/jb", 501, 501);
            }
            NSString *bootstrapReason2 = nil;
            if ([self canBootstrapInCurrentContext:&bootstrapReason2]) {
                [self appendCommandLog:@"[preflight] bootstrap probe passed (fallback), continuing without uid=0\n"];
                return nil;
            }

            return [NSString stringWithFormat:@"Не удалось получить root (uid=0), и rootless-проверка apt не прошла: %@", reason ?: @"unknown"];
        }
    }
    return nil;
}

- (void)appendInstallEnvironmentSnapshot {
    LaraManager *mgr = [LaraManager shared];
    NSString *selectedMethod = [[NSUserDefaults standardUserDefaults] stringForKey:@"selectedmethod"] ?: @"sbx";
    NSString *aptGet = [self firstExistingExecutable:@[@"/var/mobile/jb/usr/bin/apt-get", @"/usr/bin/apt-get"]];
    NSString *dpkg = [self firstExistingExecutable:@[@"/var/mobile/jb/usr/bin/dpkg", @"/usr/bin/dpkg"]];
    NSString *uicache = [self firstExistingExecutable:@[@"/var/mobile/jb/usr/bin/uicache", @"/usr/bin/uicache"]];
    [self appendCommandLog:[NSString stringWithFormat:@"[env] build=%@ uid=%d gid=%d method=%@ ds_ready=%d sbx_ready=%d vfs_ready=%d latest=%@\n",
                            kInstallerRuntimeTag,
                            getuid(),
                            getgid(),
                            selectedMethod,
                            (int)mgr.dsReady,
                            (int)mgr.sbxReady,
                            (int)vfs_isready(),
                            self.latestVersion ?: @"unknown"]];
    [self appendCommandLog:[NSString stringWithFormat:@"[env] apt=%@ dpkg=%@ uicache=%@\n",
                            aptGet ?: @"(missing)",
                            dpkg ?: @"(missing)",
                            uicache ?: @"(missing)"]];
}

- (BOOL)verifyInstallPrerequisitesWithError:(NSError **)err aptPath:(NSString *)aptGet {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSMutableArray<NSString *> *missing = [NSMutableArray array];
    NSArray<NSString *> *dpkgCandidates = lara_bootstrap_dpkg_status_candidates();
    NSString *dpkgStatus = lara_first_existing_path(dpkgCandidates);

    if (!aptGet.length) {
        [missing addObject:@"apt-get"]; 
    }

    NSString *sourcesDir = @"/var/mobile/jb/etc/apt/sources.list.d";
    NSString *sileoRepoPath = [sourcesDir stringByAppendingPathComponent:@"sileo.sources"];

    if (!dpkgStatus.length) {
        [missing addObject:[dpkgCandidates componentsJoinedByString:@" | "]];
    }
    if (![fm fileExistsAtPath:sourcesDir]) {
        [missing addObject:sourcesDir];
    }
    if (![fm fileExistsAtPath:sileoRepoPath]) {
        [missing addObject:sileoRepoPath];
    }

    if (missing.count > 0) {
        if (err) {
            *err = [NSError errorWithDomain:@"SileoInstaller"
                                       code:1010
                                   userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"Missing install prerequisites: %@", [missing componentsJoinedByString:@", "]]}];
        }
        return NO;
    }

    [self appendCommandLog:[NSString stringWithFormat:@"[verify:pre-apt] apt=%@ dpkg_status=%@ repo=%@\n", aptGet, dpkgStatus ?: @"(missing)", sileoRepoPath]];
    [self appendCommandLog:@"[verify:pre-apt] core apt environment looks ready\n"];
    return YES;
}

- (BOOL)verifySileoInstallationWithError:(NSError **)err {
    NSString *statusPath = lara_first_existing_path(lara_bootstrap_dpkg_status_candidates());
    NSData *statusData = [NSData dataWithContentsOfFile:statusPath options:0 error:nil];
    if (!statusData.length) {
        if (err) {
            *err = [NSError errorWithDomain:@"SileoInstaller"
                                       code:1011
                                   userInfo:@{NSLocalizedDescriptionKey: @"dpkg status file is missing after install"}];
        }
        return NO;
    }

    NSString *statusText = [[NSString alloc] initWithData:statusData encoding:NSUTF8StringEncoding];
    if (!statusText.length) {
        statusText = [[NSString alloc] initWithData:statusData encoding:NSISOLatin1StringEncoding];
    }

    NSRange packageRange = [statusText rangeOfString:@"Package: org.coolstar.sileo"];
    if (packageRange.location == NSNotFound) {
        if (err) {
            *err = [NSError errorWithDomain:@"SileoInstaller"
                                       code:1012
                                   userInfo:@{NSLocalizedDescriptionKey: @"org.coolstar.sileo was not registered in dpkg status"}];
        }
        return NO;
    }

    NSUInteger remaining = statusText.length - packageRange.location;
    NSUInteger windowLength = MIN((NSUInteger)512, remaining);
    NSString *window = [statusText substringWithRange:NSMakeRange(packageRange.location, windowLength)];
    if ([window rangeOfString:@"Status: install ok installed"].location == NSNotFound) {
        if (err) {
            *err = [NSError errorWithDomain:@"SileoInstaller"
                                       code:1013
                                   userInfo:@{NSLocalizedDescriptionKey: @"Sileo package entry exists but is not marked install ok installed"}];
        }
        return NO;
    }

    NSArray<NSString *> *appCandidates = @[@"/var/mobile/jb/Applications/Sileo.app", @"/Applications/Sileo.app"];
    NSString *foundApp = nil;
    NSFileManager *fm = [NSFileManager defaultManager];
    for (NSString *candidate in appCandidates) {
        BOOL isDir = NO;
        if ([fm fileExistsAtPath:candidate isDirectory:&isDir] && isDir) {
            foundApp = candidate;
            break;
        }
    }

    [self appendCommandLog:[NSString stringWithFormat:@"[verify:post-apt] dpkg entry ok, app_path=%@\n", foundApp ?: @"(not found yet)"]];
    return YES;
}

- (BOOL)canRunAptInCurrentContext:(NSString **)reason {
    [self appendCommandLog:@"[preflight:probe] starting rootless apt capability check\n"];
    NSString *aptGet = [self firstExistingExecutable:@[@"/var/mobile/jb/usr/bin/apt-get", @"/usr/bin/apt-get"]];
    if (!aptGet) {
        if (reason) *reason = @"apt-get not found";
        [self appendCommandLog:@"[preflight:probe:FAIL] apt-get not found in /var/mobile/jb/usr/bin or /usr/bin\n"];
        return NO;
    }
    [self appendCommandLog:[NSString stringWithFormat:@"[preflight:probe:PASS] found apt-get at %@\n", aptGet]];

    NSString *verOut = nil;
    int verRc = [self runCommand:@[aptGet, @"--version"] output:&verOut];
    [self appendCommandOutputForCommand:[NSString stringWithFormat:@"%@ --version", aptGet] output:verOut exitCode:verRc];
    if (verRc != 0) {
        if (reason) *reason = [NSString stringWithFormat:@"apt-get is not executable in current context (rc=%d)", verRc];
        [self appendCommandLog:[NSString stringWithFormat:@"[preflight:probe:FAIL] apt-get --version rc=%d\n", verRc]];
        return NO;
    }
    [self appendCommandLog:@"[preflight:probe:PASS] apt-get --version succeeded\n"];

    NSString *sourcesDir = @"/var/mobile/jb/etc/apt/sources.list.d";
    NSError *mkErr = nil;
    if (!_sileo_ensure_directory(sourcesDir, &mkErr)) {
            if (reason) *reason = [NSString stringWithFormat:@"cannot create %@: %@", sourcesDir, mkErr.localizedDescription ?: @"unknown"];
            [self appendCommandLog:[NSString stringWithFormat:@"[preflight:probe:FAIL] cannot create %@: %@\n", sourcesDir, mkErr.localizedDescription ?: @"unknown"]];
            return NO;
    }
    [self appendCommandLog:[NSString stringWithFormat:@"[preflight:probe:PASS] sources dir ready: %@\n", sourcesDir]];

    NSString *probePath = [sourcesDir stringByAppendingPathComponent:@".lara_probe"];
    [self appendCommandLog:[NSString stringWithFormat:@"[preflight:probe] write-test path=%@\n", probePath]];
    NSError *wrErr = nil;
    BOOL wrote = [@"probe\n" writeToFile:probePath atomically:NO encoding:NSUTF8StringEncoding error:&wrErr];
    if (!wrote) {
        if (reason) *reason = [NSString stringWithFormat:@"cannot write in %@: %@", sourcesDir, wrErr.localizedDescription ?: @"unknown"];
        [self appendCommandLog:[NSString stringWithFormat:@"[preflight:probe:FAIL] cannot write in %@: %@\n", sourcesDir, wrErr.localizedDescription ?: @"unknown"]];
        return NO;
    }
    [[NSFileManager defaultManager] removeItemAtPath:probePath error:nil];
    [self appendCommandLog:@"[preflight:probe:PASS] writable probe succeeded\n"];

    return YES;
}

- (BOOL)canBootstrapInCurrentContext:(NSString **)reason {
    if (g_sileo_diagnostic_stage_root) {
        return YES; // Allow installation if a diagnostic stage root is established
    }
    
    [self appendCommandLog:@"[preflight:bootstrap-probe] starting bootstrap capability check\n"];

    NSFileManager *fm = [NSFileManager defaultManager];
    BOOL markerExists = [fm fileExistsAtPath:kBootstrapInstalledMarker];
    NSString *dpkgStatusPath = lara_first_existing_path(lara_bootstrap_dpkg_status_candidates());
    BOOL dpkgExists = (dpkgStatusPath.length > 0);
    if (markerExists || dpkgExists) {
        [self appendCommandLog:[NSString stringWithFormat:@"[preflight:bootstrap-probe] marker=%@ dpkg=%@, skipping bootstrap probe\n",
                                markerExists ? @"yes" : @"no",
                                dpkgExists ? @"yes" : @"no"]];
        if (reason) *reason = nil;
        return YES;
    }

    NSString *bootstrapRootReason = nil;
    if (![self ensureBootstrapRootDirectoryWithReason:&bootstrapRootReason]) {
        if (reason) *reason = bootstrapRootReason ?: @"не удалось подготовить bootstrap root";
        [self appendCommandLog:[NSString stringWithFormat:@"[preflight:bootstrap-probe:FAIL] bootstrap root setup failed: %@\n",
                                bootstrapRootReason ?: @"unknown"]];
        return NO;
    }

    NSString *jbRoot = lara_bootstrap_root();
    NSString *jbVarMobile = [jbRoot stringByAppendingPathComponent:@"var/mobile"];
    NSMutableArray<NSString *> *bootstrapProbePaths = [NSMutableArray arrayWithObjects:
                                                      jbRoot,
                                                      lara_bootstrap_private_root(),
                                                      jbVarMobile,
                                                      [lara_bootstrap_private_root() stringByAppendingPathComponent:@"var/mobile"],
                                                      nil];
    NSString *resourcePath = [NSBundle mainBundle].resourcePath;
    if (resourcePath.length) {
        [bootstrapProbePaths addObject:resourcePath];
        NSString *resourceDir = resourcePath.stringByDeletingLastPathComponent;
        if (resourceDir.length) [bootstrapProbePaths addObject:resourceDir];
    }
    [self prepareSandboxExtensionsForBootstrapPaths:bootstrapProbePaths];

    NSString *extractorReason = nil;
    if (![self isInProcessBootstrapExtractorAvailableWithReason:&extractorReason]) {
        if (reason) *reason = extractorReason ?: @"libarchive runtime is unavailable";
        [self appendCommandLog:[NSString stringWithFormat:@"[preflight:bootstrap-probe:FAIL] in-process extractor unavailable: %@\n", extractorReason ?: @"unknown"]];
        return NO;
    }
    [self appendCommandLog:@"[preflight:bootstrap-probe:PASS] libarchive runtime is available\n"];

    NSError *mkdirErr = nil;
    if (!_sileo_ensure_directory(jbRoot, &mkdirErr)) {
        if (reason) *reason = [NSString stringWithFormat:@"не удалось создать bootstrap root: %@", mkdirErr.localizedDescription ?: @"unknown"];
        [self appendCommandLog:[NSString stringWithFormat:@"[preflight:bootstrap-probe:FAIL] bootstrap root mkdir failed: %@\n", mkdirErr.localizedDescription ?: @"unknown"]];
        return NO;
    }

    NSString *probeDir = [jbRoot stringByAppendingPathComponent:@".lara_bootstrap_probe"];
    NSString *probeFile = [probeDir stringByAppendingPathComponent:@"write-test"];
    [fm removeItemAtPath:probeDir error:nil];
    if (![fm createDirectoryAtPath:probeDir withIntermediateDirectories:YES attributes:nil error:&mkdirErr]) {
        if (reason) *reason = [NSString stringWithFormat:@"bootstrap root не writable: %@", mkdirErr.localizedDescription ?: @"unknown"];
        [self appendCommandLog:[NSString stringWithFormat:@"[preflight:bootstrap-probe:FAIL] probe dir create failed: %@\n", mkdirErr.localizedDescription ?: @"unknown"]];
        return NO;
    }

    NSError *probeErr = nil;
    NSData *probeData = [@"lara-bootstrap-probe\n" dataUsingEncoding:NSUTF8StringEncoding];
    BOOL wroteProbe = [probeData writeToFile:probeFile options:NSDataWritingAtomic error:&probeErr];
    [fm removeItemAtPath:probeDir error:nil];
    if (!wroteProbe) {
        if (reason) *reason = [NSString stringWithFormat:@"bootstrap root не writable для файлов: %@", probeErr.localizedDescription ?: @"unknown"];
        [self appendCommandLog:[NSString stringWithFormat:@"[preflight:bootstrap-probe:FAIL] probe file write failed: %@\n", probeErr.localizedDescription ?: @"unknown"]];
        return NO;
    }

    [self appendCommandLog:@"[preflight:bootstrap-probe:PASS] writable bootstrap root probe succeeded\n"];
    return YES;
}

- (BOOL)ensureBootstrapRootDirectoryWithReason:(NSString **)reason {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *bootstrapRoot = lara_bootstrap_root();
    if ([fm fileExistsAtPath:bootstrapRoot]) {
        if (reason) *reason = nil;
        return YES;
    }

    NSString *mkdirTool = [self firstExistingExecutable:@[@"/bin/mkdir", @"/usr/bin/mkdir"]];
    NSString *chmodTool = [self firstExistingExecutable:@[@"/bin/chmod", @"/usr/bin/chmod"]];
    NSString *chownTool = [self firstExistingExecutable:@[@"/usr/sbin/chown", @"/usr/bin/chown", @"/bin/chown"]];

    NSMutableArray<NSString *> *bootstrapRootPaths = [NSMutableArray arrayWithObjects:@"/var", @"/private/var", bootstrapRoot, lara_bootstrap_private_root(), nil];
    for (NSString *toolPath in @[mkdirTool ?: @"", chmodTool ?: @"", chownTool ?: @""]) {
        if (toolPath.length) {
            [bootstrapRootPaths addObject:toolPath];
            NSString *toolDir = toolPath.stringByDeletingLastPathComponent;
            if (toolDir.length) {
                [bootstrapRootPaths addObject:toolDir];
            }
        }
    }
    [self prepareSandboxExtensionsForBootstrapPaths:bootstrapRootPaths];

    NSError *mkdirErr = nil;
    if ([fm createDirectoryAtPath:bootstrapRoot withIntermediateDirectories:YES attributes:nil error:&mkdirErr]) {
        [self appendCommandLog:[NSString stringWithFormat:@"[bootstrap-root] normal mkdir succeeded for %@\n", bootstrapRoot]];
        if (reason) *reason = nil;
        return YES;
    }

    [self appendCommandLog:[NSString stringWithFormat:@"[bootstrap-root] normal mkdir failed: %@\n",
                            mkdirErr.localizedDescription ?: @"unknown"]];

    if (mkdirTool.length) {
        NSString *mkdirOut = nil;
        int mkdirRc = [self runCommand:@[mkdirTool, @"-p", bootstrapRoot] output:&mkdirOut];
        [self appendCommandOutputForCommand:[NSString stringWithFormat:@"%@ -p %@", mkdirTool, bootstrapRoot]
                                     output:mkdirOut
                                   exitCode:mkdirRc];
        [self appendCommandLog:[NSString stringWithFormat:@"[bootstrap-root] mkdir command rc=%d exists=%@\n",
                                mkdirRc,
                                [fm fileExistsAtPath:bootstrapRoot] ? @"yes" : @"no"]];
    } else {
        [self appendCommandLog:@"[bootstrap-root] no system mkdir tool found for root-persona attempt\n"];
    }

    if ([fm fileExistsAtPath:bootstrapRoot] && chownTool.length) {
        NSString *chownOut = nil;
        int chownRc = [self runCommand:@[chownTool, @"501:501", bootstrapRoot] output:&chownOut];
        [self appendCommandOutputForCommand:[NSString stringWithFormat:@"%@ 501:501 %@", chownTool, bootstrapRoot]
                                     output:chownOut
                                   exitCode:chownRc];
        [self appendCommandLog:[NSString stringWithFormat:@"[bootstrap-root] chown command rc=%d\n", chownRc]];
    }

    if ([fm fileExistsAtPath:bootstrapRoot] && chmodTool.length) {
        NSString *chmodOut = nil;
        int chmodRc = [self runCommand:@[chmodTool, @"0755", bootstrapRoot] output:&chmodOut];
        [self appendCommandOutputForCommand:[NSString stringWithFormat:@"%@ 0755 %@", chmodTool, bootstrapRoot]
                                     output:chmodOut
                                   exitCode:chmodRc];
        [self appendCommandLog:[NSString stringWithFormat:@"[bootstrap-root] chmod command rc=%d\n", chmodRc]];
    }

    if ([fm fileExistsAtPath:bootstrapRoot]) {
        if (reason) *reason = nil;
        return YES;
    }

    // VFS‑fallback имеет смысл только для исторического /var/mobile/jb, чтобы не трогать
    // inode-ы /var лишний раз. Для userland‑корня под mobile он не нужен.
    if (vfs_isready() && [bootstrapRoot isEqualToString:@"/var/mobile/jb"]) {
        [self appendCommandLog:@"[bootstrap-root] trying VFS mkdir fallback for /var/mobile/jb...\n"];
        int mkrc = vfs_mkdir_p("/var/mobile/jb", 501, 501);
        [self appendCommandLog:[NSString stringWithFormat:@"[bootstrap-root] VFS mkdir rc=%d exists=%@\n",
                                mkrc,
                                [fm fileExistsAtPath:bootstrapRoot] ? @"yes" : @"no"]];
        if (mkrc == 0 || [fm fileExistsAtPath:bootstrapRoot]) {
            if (reason) *reason = nil;
            return YES;
        }
    }

    // Diagnostic stage-root fallback: try to create a writable directory in
    // other known writable locations (for diagnostics only — not a final root).
    // NOTE: /var/* may still be blocked by sandbox; include container paths too.
    NSString *docsDir = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    NSString *tmpDir = NSTemporaryDirectory();
    NSMutableArray<NSString *> *stageCandidates = [NSMutableArray arrayWithArray:@[@"/var/tmp/lara-stage-jb", @"/var/mobile/lara-stage-jb"]];
    if (tmpDir.length) {
        [stageCandidates addObject:[tmpDir stringByAppendingPathComponent:@"lara-stage-jb"]];
    }
    if (docsDir.length) {
        [stageCandidates addObject:[docsDir stringByAppendingPathComponent:@"lara-stage-jb"]];
    }
    for (NSString *cand in stageCandidates) {
        NSError *stageErr = nil;
        if (!cand.length) continue;
        if ([[NSFileManager defaultManager] fileExistsAtPath:cand]) {
            g_sileo_diagnostic_stage_root = [cand copy];
            [self appendCommandLog:[NSString stringWithFormat:@"[bootstrap-root] diagnostic stage-root already exists at %@\n", cand]];
            break;
        }
        if ([[NSFileManager defaultManager] createDirectoryAtPath:cand withIntermediateDirectories:YES attributes:nil error:&stageErr]) {
            g_sileo_diagnostic_stage_root = [cand copy];
            [self appendCommandLog:[NSString stringWithFormat:@"[bootstrap-root] diagnostic stage-root created at %@ (for extraction testing only)\n", cand]];
            break;
        } else {
            [self appendCommandLog:[NSString stringWithFormat:@"[bootstrap-root] diagnostic stage-root create failed for %@: %@\n", cand, stageErr.localizedDescription ?: @"unknown"]];
        }
    }

    if (g_sileo_diagnostic_stage_root) {
        [self prepareSandboxExtensionsForBootstrapPaths:@[g_sileo_diagnostic_stage_root, @"/var", @"/private/var"]];
        if (reason) {
            *reason = [NSString stringWithFormat:@"bootstrap root отсутствует после normal mkdir, root-persona mkdir и VFS fallback (%@). Diagnostic stage-root created at %@ for extraction testing.",
                       mkdirErr.localizedDescription ?: @"unknown", g_sileo_diagnostic_stage_root ?: @"(unknown)"];
        }
    } else {
        if (reason) {
            *reason = [NSString stringWithFormat:@"bootstrap root отсутствует после normal mkdir, root-persona mkdir и VFS fallback (%@)",
                       mkdirErr.localizedDescription ?: @"unknown"];
        }
    }
    return NO;
}

- (BOOL)ensureBootstrapInstalledIfNeeded:(NSError **)err {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *aptGet = [self firstExistingExecutable:@[[lara_bootstrap_root() stringByAppendingPathComponent:@"usr/bin/apt-get"], @"/usr/bin/apt-get"]];
    NSString *dpkgStatus = lara_first_existing_path(lara_bootstrap_dpkg_status_candidates());
    BOOL markerExists = [fm fileExistsAtPath:kBootstrapInstalledMarker];
    BOOL dpkgExists = (dpkgStatus.length > 0);
    if ((aptGet && dpkgExists) || (markerExists && [fm fileExistsAtPath:lara_bootstrap_root()])) {
        [self appendCommandLog:[NSString stringWithFormat:@"[bootstrap] existing bootstrap detected (marker=%@ dpkg=%@), skipping download\n",
                                markerExists ? @"yes" : @"no",
                                dpkgExists ? @"yes" : @"no"]];
        return YES;
    }

    if (getuid() != 0) {
        NSString *bootstrapReason = nil;
        if (![self canBootstrapInCurrentContext:&bootstrapReason]) {
            // If a diagnostic stage-root exists, attempt a diagnostic in-process extraction
            // into that directory to verify the extractor and staging behavior. This is
            // strictly diagnostic and will not be considered a successful bootstrap.
            if (g_sileo_diagnostic_stage_root) {
                [self appendCommandLog:[NSString stringWithFormat:@"[bootstrap:diagnostic] attempting diagnostic extraction into %@\n", g_sileo_diagnostic_stage_root]];
                NSString *diagBundled = [self bundledBootstrapArchivePath];
                NSData *diagData = nil;
                NSError *diagErr = nil;
                if (diagBundled.length) {
                    diagData = [NSData dataWithContentsOfFile:diagBundled options:0 error:&diagErr];
                } else {
                    NSString *bootstrapVersion = [self dopamineBootstrapVersion];
                    if (bootstrapVersion.length) {
                        NSString *urlString = [NSString stringWithFormat:kProcursusBootstrapURLFormat, bootstrapVersion];
                        diagData = [NSData dataWithContentsOfURL:[NSURL URLWithString:urlString] options:0 error:&diagErr];
                    }
                }
                if (diagData.length) {
                    NSString *tmpDiag = [NSTemporaryDirectory() stringByAppendingPathComponent:@"lara_bootstrap_diag.tar.zst"];
                    if ([diagData writeToFile:tmpDiag options:NSDataWritingAtomic error:&diagErr]) {
                        NSError *extractErr = nil;
                        BOOL exok = [self extractBootstrapArchiveInProcessAtPath:tmpDiag destination:g_sileo_diagnostic_stage_root error:&extractErr];
                        [self appendCommandLog:[NSString stringWithFormat:@"[bootstrap:diagnostic] extraction result: %@\n", exok ? @"ok" : @"fail"]];
                        if (!exok) {
                            [self appendCommandLog:[NSString stringWithFormat:@"[bootstrap:diagnostic] extraction failed: %@\n", extractErr.localizedDescription ?: @"unknown"]];
                        } else {
                            [self appendCommandLog:[NSString stringWithFormat:@"[bootstrap:diagnostic] extraction succeeded into %@ (diagnostic only)\n", g_sileo_diagnostic_stage_root]];
                        }
                        [[NSFileManager defaultManager] removeItemAtPath:tmpDiag error:nil];
                    } else {
                        [self appendCommandLog:[NSString stringWithFormat:@"[bootstrap:diagnostic] cannot write tmp archive: %@\n", diagErr.localizedDescription ?: @"unknown"]];
                    }
                } else {
                    [self appendCommandLog:[NSString stringWithFormat:@"[bootstrap:diagnostic] cannot retrieve bootstrap archive for diagnostic: %@\n", diagErr.localizedDescription ?: @"unknown"]];
                }
            }

            if (err) {
                *err = [NSError errorWithDomain:@"SileoInstaller"
                                           code:1006
                                       userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"Bootstrap blocked before extraction: %@", bootstrapReason ?: @"unknown"]}];
            }
            [self appendCommandLog:[NSString stringWithFormat:@"[bootstrap] fail-fast: %@\n", bootstrapReason ?: @"unknown"]];
            return NO;
        }
    }

    NSData *zstdData = nil;
    NSString *bundledPath = [self bundledBootstrapArchivePath];

    if (bundledPath.length) {
        [self appendCommandLog:[NSString stringWithFormat:@"[bootstrap] using bundled archive: %@\n", bundledPath]];
        zstdData = [NSData dataWithContentsOfFile:bundledPath options:0 error:err];
        if (!zstdData.length) {
            [self appendCommandLog:[NSString stringWithFormat:@"[bootstrap] bundled archive read failed: %@\n", (*err).localizedDescription ?: @"unknown error"]];
            return NO;
        }
    } else {
        NSString *bootstrapVersion = [self dopamineBootstrapVersion];
        if (!bootstrapVersion.length) {
            if (err) {
                *err = [NSError errorWithDomain:@"SileoInstaller"
                                           code:1001
                                       userInfo:@{NSLocalizedDescriptionKey: @"Unsupported CF version for Procursus bootstrap URL and no bundled bootstrap found"}];
            }
            [self appendCommandLog:@"[bootstrap] bundled archive not found and CF version is unsupported for Procursus URL\n"];
            return NO;
        }
        NSString *urlString = [NSString stringWithFormat:kProcursusBootstrapURLFormat, bootstrapVersion];
        [self appendCommandLog:[NSString stringWithFormat:@"[bootstrap] bundled archive not found, downloading %@\n", urlString]];
        zstdData = [NSData dataWithContentsOfURL:[NSURL URLWithString:urlString] options:0 error:err];
        if (!zstdData.length) {
            [self appendCommandLog:[NSString stringWithFormat:@"[bootstrap] download failed: %@\n", (*err).localizedDescription ?: @"unknown error"]];
            return NO;
        }
    }

    NSString *tmpZstd = [NSTemporaryDirectory() stringByAppendingPathComponent:@"lara_bootstrap.tar.zst"];
    if (![zstdData writeToFile:tmpZstd options:NSDataWritingAtomic error:err]) {
        [self appendCommandLog:[NSString stringWithFormat:@"[bootstrap] cannot write temp archive: %@\n", (*err).localizedDescription ?: @"unknown error"]];
        return NO;
    }

    if (getuid() != 0) {
        uint64_t ourProc = ds_get_our_proc();
        if (ourProc != 0) {
            [self appendCommandLog:@"[bootstrap] applying secondary sbx_escape before extraction...\n"];
            int esc2 = sbx_escape(ourProc);
            [self appendCommandLog:[NSString stringWithFormat:@"[bootstrap] secondary sbx_escape rc=%d\n", esc2]];
        }
        // Ensure /var/mobile/jb exists via VFS before extraction
        if (vfs_isready() && ![[NSFileManager defaultManager] fileExistsAtPath:@"/var/mobile/jb"]) {
            [self appendCommandLog:@"[bootstrap] creating /var/mobile/jb via VFS before extraction...\n"];
            int mkrc = vfs_mkdir_p("/var/mobile/jb", 501, 501);
            [self appendCommandLog:[NSString stringWithFormat:@"[bootstrap] vfs_mkdir_p rc=%d\n", mkrc]];
        }
    }

    NSMutableArray<NSString *> *sandboxPaths = [NSMutableArray arrayWithObjects:@"/var/mobile/jb", @"/private/var/mobile/jb", @"/var/mobile/jb/var/mobile", @"/private/var/mobile/jb/var/mobile", nil];
    NSString *resourcePath = [NSBundle mainBundle].resourcePath;
    if (resourcePath.length) [sandboxPaths addObject:resourcePath];
    [self prepareSandboxExtensionsForBootstrapPaths:sandboxPaths];

    BOOL extracted = NO;
    NSError *inProcessErr = nil;
    [self appendCommandLog:[NSString stringWithFormat:@"[bootstrap] trying in-process libarchive extraction from %@\n", tmpZstd]];
    extracted = [self extractBootstrapArchiveInProcessAtPath:tmpZstd destination:@"/" error:&inProcessErr];
    if (!extracted) {
        [self appendCommandLog:[NSString stringWithFormat:@"[bootstrap] in-process extraction failed, falling back to legacy helpers: %@\n",
                                inProcessErr.localizedDescription ?: @"unknown error"]];

        NSString *bundledTar = [self bundledHelperExecutable:@"tar"];
        NSString *bundledBsdtar = [self bundledHelperExecutable:@"bsdtar"];
        NSString *bundledZstd = [self bundledHelperExecutable:@"zstd"];
        NSString *bundledTarProcursus = [self bundledHelperExecutable:@"tar-procursus"];
        NSString *bundledBash = [self bundledHelperExecutable:@"bash"];
        if (bundledTar) {
            [self appendCommandLog:[NSString stringWithFormat:@"[bootstrap] found bundled tar helper: %@\n", bundledTar]];
        }
        if (bundledBsdtar) {
            [self appendCommandLog:[NSString stringWithFormat:@"[bootstrap] found bundled bsdtar helper: %@\n", bundledBsdtar]];
        }
        if (bundledZstd) {
            [self appendCommandLog:[NSString stringWithFormat:@"[bootstrap] found bundled zstd helper: %@\n", bundledZstd]];
        }
        if (bundledTarProcursus) {
            [self appendCommandLog:[NSString stringWithFormat:@"[bootstrap] found bundled tar-procursus helper: %@\n", bundledTarProcursus]];
        }
        if (bundledBash) {
            [self appendCommandLog:[NSString stringWithFormat:@"[bootstrap] found bundled bash helper: %@\n", bundledBash]];
        }

        for (NSString *helperPath in @[bundledTar ?: @"", bundledBsdtar ?: @"", bundledZstd ?: @"", bundledTarProcursus ?: @"", bundledBash ?: @""]) {
            if (helperPath.length) {
                [sandboxPaths addObject:helperPath];
                NSString *helperDir = helperPath.stringByDeletingLastPathComponent;
                if (helperDir.length) [sandboxPaths addObject:helperDir];
            }
        }
        [self prepareSandboxExtensionsForBootstrapPaths:sandboxPaths];

        NSString *stagedTar = [self stageHelperToJBTools:@"tar"];
        NSString *stagedTarProcursus = [self stageHelperToJBTools:@"tar-procursus"];
        NSString *stagedBsdtar = [self stageHelperToJBTools:@"bsdtar"];
        NSString *stagedZstd = [self stageHelperToJBTools:@"zstd"];
        NSString *stagedBash = [self stageHelperToJBTools:@"bash"];
        [self stageHelperToJBTools:@"libiosexec.1.dylib"];
        [self stageHelperToJBTools:@"libintl.8.dylib"];

        if (stagedTar) {
            [self appendCommandLog:[NSString stringWithFormat:@"[bootstrap] staged tar helper: %@\n", stagedTar]];
        }
        if (stagedTarProcursus) {
            [self appendCommandLog:[NSString stringWithFormat:@"[bootstrap] staged tar-procursus helper: %@\n", stagedTarProcursus]];
        }
        if (stagedBsdtar && stagedZstd) {
            [self appendCommandLog:[NSString stringWithFormat:@"[bootstrap] staged bsdtar+zstd helpers: %@ + %@\n", stagedBsdtar, stagedZstd]];
        }
        if (stagedBash) {
            [self appendCommandLog:[NSString stringWithFormat:@"[bootstrap] staged bash helper: %@\n", stagedBash]];
        }

        NSString *shell = [self bootstrapShellExecutable];
        NSArray<NSArray<NSString *> *> *extractAttempts = @[
            stagedTar ? @[stagedTar, @"-xf", tmpZstd, @"-C", @"/"] : @[],
            stagedTarProcursus ? @[stagedTarProcursus, @"-xf", tmpZstd, @"-C", @"/"] : @[],
            (stagedBsdtar && stagedZstd) ? @[stagedBsdtar, @"-I", stagedZstd, @"-xf", tmpZstd, @"-C", @"/"] : @[],
            bundledTar ? @[bundledTar, @"-xf", tmpZstd, @"-C", @"/"] : @[],
            bundledTarProcursus ? @[bundledTarProcursus, @"-xf", tmpZstd, @"-C", @"/"] : @[],
            (bundledBsdtar && bundledZstd) ? @[bundledBsdtar, @"-I", bundledZstd, @"-xf", tmpZstd, @"-C", @"/"] : @[],
            shell ? @[shell, @"-c", [NSString stringWithFormat:@"/usr/bin/tar -xf '%@' -C /", tmpZstd]] : @[],
            shell ? @[shell, @"-c", [NSString stringWithFormat:@"/usr/bin/bsdtar -xf '%@' -C /", tmpZstd]] : @[],
            @[@"/usr/bin/tar", @"-xf", tmpZstd, @"-C", @"/"],
            @[@"/usr/bin/bsdtar", @"-xf", tmpZstd, @"-C", @"/"],
            @[@"/bin/tar", @"-xf", tmpZstd, @"-C", @"/"],
            @[@"/usr/bin/tar", @"--use-compress-program", @"zstd", @"-xf", tmpZstd, @"-C", @"/"],
            @[@"/usr/bin/tar", @"-I", @"zstd", @"-xf", tmpZstd, @"-C", @"/"],
            @[@"/usr/bin/bsdtar", @"-I", @"zstd", @"-xf", tmpZstd, @"-C", @"/"],
            @[@"/var/mobile/jb/usr/bin/tar", @"--use-compress-program", @"/var/mobile/jb/usr/bin/zstd", @"-xf", tmpZstd, @"-C", @"/"]
        ];

        NSString *lastOut = nil;
        for (NSArray<NSString *> *cmd in extractAttempts) {
            if (cmd.count == 0) {
                continue;
            }
            NSString *bin = cmd.firstObject ?: @"(unknown)";
            int rc = [self runCommand:cmd output:&lastOut];
            [self appendCommandOutputForCommand:[cmd componentsJoinedByString:@" "] output:lastOut exitCode:rc];
            if (rc == 0) {
                [self appendCommandLog:[NSString stringWithFormat:@"[bootstrap] extraction attempt passed: %@\n", bin]];
                extracted = YES;
                break;
            }
            [self appendCommandLog:[NSString stringWithFormat:@"[bootstrap] extraction attempt failed: %@ (rc=%d)\n", bin, rc]];
        }
    }

    [fm removeItemAtPath:tmpZstd error:nil];

    if (!extracted) {
        [self appendCommandLog:@"[bootstrap] all extraction attempts failed\n"];
        if (err) {
            *err = [NSError errorWithDomain:@"SileoInstaller"
                                       code:1002
                                   userInfo:@{NSLocalizedDescriptionKey: inProcessErr.localizedDescription ?: @"Failed to extract bootstrap archive (in-process and legacy extractors failed)"}];
        }
        return NO;
    }

    [self appendCommandLog:@"[bootstrap] archive extracted\n"];
    [self fixBootstrapPermissionsForRootless];
    BOOL hasMarker = [fm fileExistsAtPath:kBootstrapInstalledMarker];
    BOOL hasJBRoot = [fm fileExistsAtPath:@"/var/mobile/jb"];
    BOOL dpkgExistsAfterExtract = [fm fileExistsAtPath:dpkgStatus];
    [self appendCommandLog:[NSString stringWithFormat:@"[bootstrap:verify] marker=%@ jb_root=%@ dpkg=%@ uid=%d\n",
                            hasMarker ? @"yes" : @"no",
                            hasJBRoot ? @"yes" : @"no",
                            dpkgExistsAfterExtract ? @"yes" : @"no",
                            getuid()]];
    [self appendCommandLog:[NSString stringWithFormat:@"[bootstrap:diagnose] dpkg status exists=%@ at %@\n", dpkgExistsAfterExtract ? @"yes" : @"no", dpkgStatus]];
    if (!dpkgExistsAfterExtract) {
        if (err) {
            *err = [NSError errorWithDomain:@"SileoInstaller"
                                       code:1005
                                   userInfo:@{NSLocalizedDescriptionKey: @"Bootstrap extracted but the dpkg status database is missing"}];
        }
        return NO;
    }

    [self prepareSandboxExtensionsForBootstrapPaths:@[@"/var/mobile/jb", @"/private/var/mobile/jb", @"/var/mobile/jb/bin", @"/var/mobile/jb/usr/bin", @"/var/mobile/jb/bin/sh", @"/var/mobile/jb/usr/bin/sh", @"/var/mobile/jb/prep_bootstrap.sh"]];

    NSString *prep = @"/var/mobile/jb/prep_bootstrap.sh";
    if ([fm fileExistsAtPath:prep]) {
        NSString *prepShell = [self bootstrapShellExecutable];
        if (!prepShell.length) {
            if (err) {
                *err = [NSError errorWithDomain:@"SileoInstaller"
                                           code:1003
                                       userInfo:@{NSLocalizedDescriptionKey: @"prep_bootstrap.sh найден, но shell helper недоступен"}];
            }
            return NO;
        }
        NSString *prepOut = nil;
        int prepRc = [self runCommand:@[prepShell, prep] output:&prepOut];
        [self appendCommandOutputForCommand:[NSString stringWithFormat:@"%@ %@", prepShell, prep] output:prepOut exitCode:prepRc];
        if (prepRc != 0) {
            if (err) {
                *err = [NSError errorWithDomain:@"SileoInstaller"
                                           code:1003
                                       userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"prep_bootstrap.sh failed (%d)", prepRc]}];
            }
            return NO;
        }
    } else {
        [self appendCommandLog:@"[bootstrap] prep_bootstrap.sh not found, continuing\n"];
    }

    NSString *newAptGet = [self firstExistingExecutable:@[@"/var/mobile/jb/usr/bin/apt-get", @"/usr/bin/apt-get"]];
    if (!newAptGet) {
        NSString *diag = [self aptBinaryDiagnostics];
        [self appendCommandLog:diag];
        if (err) {
            *err = [NSError errorWithDomain:@"SileoInstaller"
                                       code:1004
                                   userInfo:@{NSLocalizedDescriptionKey: @"Bootstrap extracted but apt-get still missing"}];
        }
        return NO;
    }
    return YES;
}

- (NSString *)bundledBootstrapArchivePath {
    NSString *bundledPath = [[NSBundle mainBundle] pathForResource:@"bootstrap-ssh-iphoneos-arm64" ofType:@"tar.zst"];
    if (bundledPath.length) {
        return bundledPath;
    }

    NSString *assetsPath = [[[NSBundle mainBundle] resourcePath] stringByAppendingPathComponent:[NSString stringWithFormat:@"assets/%@", kBundledBootstrapName]];
    if ([[NSFileManager defaultManager] fileExistsAtPath:assetsPath]) {
        return assetsPath;
    }
    return nil;
}

- (BOOL)isInProcessBootstrapExtractorAvailableWithReason:(NSString **)reason {
    _sileo_libarchive_api_t api;
    NSString *localReason = nil;
    BOOL ok = _sileo_load_libarchive(&api, &localReason);
    if (ok) {
        _sileo_unload_libarchive(&api);
    }
    if (!ok && reason) {
        *reason = localReason;
    }
    return ok;
}

static BOOL _sileo_zstd_decompress(NSString *zstdPath, NSString *tarPath, NSError **err) {
    FILE *fin = fopen(zstdPath.UTF8String, "rb");
    FILE *fout = fopen(tarPath.UTF8String, "wb");
    if (!fin) {
        if (err) *err = [NSError errorWithDomain:@"SileoBootstrap" code:2090 userInfo:@{NSLocalizedDescriptionKey: @"Failed to open zstd archive for reading"}];
        if (fout) fclose(fout);
        return NO;
    }
    if (!fout) {
        if (err) *err = [NSError errorWithDomain:@"SileoBootstrap" code:2091 userInfo:@{NSLocalizedDescriptionKey: @"Failed to open tar for writing"}];
        fclose(fin);
        return NO;
    }

    size_t buffInSize = ZSTD_DStreamInSize();
    void* buffIn = malloc(buffInSize);
    size_t buffOutSize = ZSTD_DStreamOutSize();
    void* buffOut = malloc(buffOutSize);

    ZSTD_DStream* const dctx = ZSTD_createDStream();
    if (dctx==NULL) {
        if (err) *err = [NSError errorWithDomain:@"SileoBootstrap" code:2092 userInfo:@{NSLocalizedDescriptionKey: @"ZSTD_createDStream failed"}];
        free(buffIn); free(buffOut); fclose(fin); fclose(fout);
        return NO;
    }

    size_t const initResult = ZSTD_initDStream(dctx);
    if (ZSTD_isError(initResult)) {
        if (err) *err = [NSError errorWithDomain:@"SileoBootstrap" code:2093 userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"ZSTD_initDStream: %s", ZSTD_getErrorName(initResult)]}];
        ZSTD_freeDStream(dctx); free(buffIn); free(buffOut); fclose(fin); fclose(fout);
        return NO;
    }

    size_t readCount;
    while ((readCount = fread(buffIn, 1, buffInSize, fin)) > 0) {
        ZSTD_inBuffer input = { buffIn, readCount, 0 };
        while (input.pos < input.size) {
            ZSTD_outBuffer output = { buffOut, buffOutSize, 0 };
            size_t const ret = ZSTD_decompressStream(dctx, &output , &input);
            if (ZSTD_isError(ret)) {
                if (err) *err = [NSError errorWithDomain:@"SileoBootstrap" code:2094 userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"ZSTD_decompressStream: %s", ZSTD_getErrorName(ret)]}];
                ZSTD_freeDStream(dctx); free(buffIn); free(buffOut); fclose(fin); fclose(fout);
                return NO;
            }
            fwrite(buffOut, 1, output.pos, fout);
        }
    }

    ZSTD_freeDStream(dctx);
    free(buffIn);
    free(buffOut);
    fclose(fin);
    fclose(fout);
    return YES;
}

- (BOOL)extractBootstrapArchiveInProcessAtPath:(NSString *)archivePath destination:(NSString *)destination error:(NSError **)err {
    if (!archivePath.length || !destination.length) {
        if (err) *err = _sileo_bootstrap_error(2001, @"bootstrap archive path or destination is missing");
        return NO;
    }

    NSString *actualArchivePath = archivePath;
    BOOL cleanupActualArchive = NO;
    if ([archivePath hasSuffix:@".zst"] || [archivePath hasSuffix:@".tar.zst"]) {
        NSString *tmpTar = [NSTemporaryDirectory() stringByAppendingPathComponent:[[NSUUID UUID] UUIDString]];
        tmpTar = [tmpTar stringByAppendingPathExtension:@"tar"];
        [[Logger shared] log:[NSString stringWithFormat:@"[bootstrap] decompressing %@ to %@", archivePath, tmpTar]];
        if (!_sileo_zstd_decompress(archivePath, tmpTar, err)) {
            [[Logger shared] log:@"[bootstrap] internal zstd decompression failed."];
            return NO;
        }
        actualArchivePath = tmpTar;
        cleanupActualArchive = YES;
    }

    _sileo_libarchive_api_t api;
    NSString *loadReason = nil;
    if (!_sileo_load_libarchive(&api, &loadReason)) {
        if (cleanupActualArchive) [[NSFileManager defaultManager] removeItemAtPath:actualArchivePath error:nil];
        if (err) *err = _sileo_bootstrap_error(2002, loadReason ?: @"libarchive runtime is unavailable");
        return NO;
    }

    _sileo_archive_t *archive = api.read_new();
    if (!archive) {
        _sileo_unload_libarchive(&api);
        if (err) *err = _sileo_bootstrap_error(2003, @"archive_read_new failed");
        return NO;
    }

    int rc = api.read_support_filter_all(archive);
    if (rc != SILEO_ARCHIVE_OK) {
        const char *archiveErr = api.error_string ? api.error_string(archive) : NULL;
        NSString *desc = archiveErr ? [NSString stringWithUTF8String:archiveErr] : @"archive_read_support_filter_all failed";
        api.read_free(archive);
        _sileo_unload_libarchive(&api);
        if (err) *err = _sileo_bootstrap_error(2004, desc);
        return NO;
    }

    if (api.read_support_format_all) {
        rc = api.read_support_format_all(archive);
    } else {
        rc = api.read_support_format_tar(archive);
    }
    if (rc != SILEO_ARCHIVE_OK) {
        const char *archiveErr = api.error_string ? api.error_string(archive) : NULL;
        NSString *desc = archiveErr ? [NSString stringWithUTF8String:archiveErr] : @"archive_read_support_format_* failed";
        api.read_free(archive);
        _sileo_unload_libarchive(&api);
        if (err) *err = _sileo_bootstrap_error(2005, desc);
        return NO;
    }

    rc = api.read_open_filename(archive, actualArchivePath.fileSystemRepresentation, 10240);
    if (rc != SILEO_ARCHIVE_OK) {
        const char *archiveErr = api.error_string ? api.error_string(archive) : NULL;
        NSString *desc = archiveErr ? [NSString stringWithUTF8String:archiveErr] : @"archive_read_open_filename failed";
        api.read_free(archive);
        _sileo_unload_libarchive(&api);
        if (cleanupActualArchive) [[NSFileManager defaultManager] removeItemAtPath:actualArchivePath error:nil];
        if (err) *err = _sileo_bootstrap_error(2006, desc);
        return NO;
    }

    NSFileManager *fm = [NSFileManager defaultManager];
    NSUInteger extractedEntries = 0;
    NSUInteger skippedEntries = 0;
    NSUInteger optionalFailures = 0;
    BOOL success = YES;
    NSError *localErr = nil;
    _sileo_archive_entry_t *entry = NULL;
    int headerRc = SILEO_ARCHIVE_OK;
    uint8_t buffer[32768];

    while ((headerRc = api.read_next_header(archive, &entry)) == SILEO_ARCHIVE_OK) {
        const char *rawPathC = api.entry_pathname ? api.entry_pathname(entry) : NULL;
        NSString *rawPath = rawPathC ? [NSString stringWithUTF8String:rawPathC] : nil;
        BOOL optionalEntry = NO;
        NSString *target = _sileo_normalize_archive_entry_target(rawPath, destination, &optionalEntry);
        if (!target.length) {
            skippedEntries++;
            if (api.read_data_skip) {
                api.read_data_skip(archive);
            }
            continue;
        }

        mode_t mode = api.entry_mode(entry);
        NSString *parent = target.stringByDeletingLastPathComponent;
        if (parent.length && ![parent isEqualToString:target] && !_sileo_ensure_directory(parent, &localErr)) {
            if (optionalEntry) {
                optionalFailures++;
                [self appendCommandLog:[NSString stringWithFormat:@"[bootstrap:libarchive] optional parent mkdir failed for %@: %@\n", target, localErr.localizedDescription ?: @"unknown"]];
                localErr = nil;
                if (api.read_data_skip) {
                    api.read_data_skip(archive);
                }
                continue;
            }
            success = NO;
            break;
        }

        if (S_ISDIR(mode)) {
            if (!_sileo_ensure_directory(target, &localErr)) {
                if (optionalEntry) {
                    optionalFailures++;
                    [self appendCommandLog:[NSString stringWithFormat:@"[bootstrap:libarchive] optional dir mkdir failed for %@: %@\n", target, localErr.localizedDescription ?: @"unknown"]];
                    localErr = nil;
                    continue;
                }
                success = NO;
                break;
            }
            chmod(target.fileSystemRepresentation, mode & 07777);
            extractedEntries++;
            continue;
        }

        if (S_ISLNK(mode) && api.entry_symlink) {
            const char *linkTarget = api.entry_symlink(entry);
            if (!linkTarget) {
                skippedEntries++;
                continue;
            }
            [fm removeItemAtPath:target error:nil];
            if (symlink(linkTarget, target.fileSystemRepresentation) != 0) {
                NSString *desc = [NSString stringWithFormat:@"symlink %@ failed: %s", target, strerror(errno)];
                if (optionalEntry) {
                    optionalFailures++;
                    [self appendCommandLog:[NSString stringWithFormat:@"[bootstrap:libarchive] optional %@\n", desc]];
                    continue;
                }
                localErr = _sileo_bootstrap_error(2007, desc);
                success = NO;
                break;
            }
            extractedEntries++;
            continue;
        }

        if (api.entry_hardlink) {
            const char *hardlinkTarget = api.entry_hardlink(entry);
            if (hardlinkTarget) {
                NSString *hardlinkRaw = [NSString stringWithUTF8String:hardlinkTarget];
                NSString *hardlinkPath = _sileo_normalize_archive_entry_target(hardlinkRaw, destination, NULL);
                if (!hardlinkPath.length) {
                    skippedEntries++;
                    continue;
                }
                [fm removeItemAtPath:target error:nil];
                if (link(hardlinkPath.fileSystemRepresentation, target.fileSystemRepresentation) != 0) {
                    NSString *desc = [NSString stringWithFormat:@"hardlink %@ -> %@ failed: %s", target, hardlinkPath, strerror(errno)];
                    if (optionalEntry) {
                        optionalFailures++;
                        [self appendCommandLog:[NSString stringWithFormat:@"[bootstrap:libarchive] optional %@\n", desc]];
                        continue;
                    }
                    localErr = _sileo_bootstrap_error(2008, desc);
                    success = NO;
                    break;
                }
                extractedEntries++;
                continue;
            }
        }

        if (!_sileo_is_bootstrap_regular_file(mode)) {
            skippedEntries++;
            if (api.read_data_skip) {
                api.read_data_skip(archive);
            }
            continue;
        }

        [fm removeItemAtPath:target error:nil];
        mode_t fileMode = (mode & 07777);
        if (fileMode == 0) {
            fileMode = 0644;
        }
        int fd = open(target.fileSystemRepresentation, O_CREAT | O_TRUNC | O_WRONLY, fileMode);
        if (fd < 0) {
            NSString *desc = [NSString stringWithFormat:@"open %@ failed: %s", target, strerror(errno)];
            if (optionalEntry) {
                optionalFailures++;
                [self appendCommandLog:[NSString stringWithFormat:@"[bootstrap:libarchive] optional %@\n", desc]];
                if (api.read_data_skip) {
                    api.read_data_skip(archive);
                }
                continue;
            }
            localErr = _sileo_bootstrap_error(2009, desc);
            success = NO;
            break;
        }

        BOOL writeOk = YES;
        ssize_t readRc = 0;
        while ((readRc = api.read_data(archive, buffer, sizeof(buffer))) > 0) {
            size_t offset = 0;
            while (offset < (size_t)readRc) {
                ssize_t wrote = write(fd, buffer + offset, (size_t)readRc - offset);
                if (wrote < 0) {
                    NSString *desc = [NSString stringWithFormat:@"write %@ failed: %s", target, strerror(errno)];
                    if (optionalEntry) {
                        optionalFailures++;
                        [self appendCommandLog:[NSString stringWithFormat:@"[bootstrap:libarchive] optional %@\n", desc]];
                    } else {
                        localErr = _sileo_bootstrap_error(2010, desc);
                        success = NO;
                    }
                    writeOk = NO;
                    break;
                }
                offset += (size_t)wrote;
            }
            if (!writeOk) {
                break;
            }
        }

        int savedErrno = errno;
        close(fd);
        if (!writeOk) {
            [fm removeItemAtPath:target error:nil];
            if (!success) {
                break;
            }
            if (api.read_data_skip) {
                api.read_data_skip(archive);
            }
            continue;
        }
        if (readRc < 0) {
            const char *archiveErr = api.error_string ? api.error_string(archive) : NULL;
            NSString *desc = archiveErr ? [NSString stringWithUTF8String:archiveErr] : [NSString stringWithFormat:@"archive_read_data failed for %@: %s", target, strerror(savedErrno)];
            if (optionalEntry) {
                optionalFailures++;
                [fm removeItemAtPath:target error:nil];
                [self appendCommandLog:[NSString stringWithFormat:@"[bootstrap:libarchive] optional %@\n", desc]];
                continue;
            }
            localErr = _sileo_bootstrap_error(2011, desc);
            success = NO;
            break;
        }

        chmod(target.fileSystemRepresentation, mode & 07777);
        extractedEntries++;
    }

    if (headerRc != SILEO_ARCHIVE_EOF && success) {
        const char *archiveErr = api.error_string ? api.error_string(archive) : NULL;
        NSString *desc = archiveErr ? [NSString stringWithUTF8String:archiveErr] : [NSString stringWithFormat:@"archive iteration failed with rc=%d", headerRc];
        localErr = _sileo_bootstrap_error(2012, desc);
        success = NO;
    }

    api.read_free(archive);
    _sileo_unload_libarchive(&api);
    if (cleanupActualArchive) {
        [[NSFileManager defaultManager] removeItemAtPath:actualArchivePath error:nil];
    }

    if (!success) {
        if (err) *err = localErr ?: _sileo_bootstrap_error(2013, @"unknown libarchive extraction failure");
        return NO;
    }

    [self appendCommandLog:[NSString stringWithFormat:@"[bootstrap:libarchive] in-process extraction ok entries=%lu skipped=%lu optional_failures=%lu\n",
                            (unsigned long)extractedEntries,
                            (unsigned long)skippedEntries,
                            (unsigned long)optionalFailures]];
    return YES;
}

- (NSString *)bootstrapShellExecutable {
    NSString *jbRoot = lara_bootstrap_root();
    NSString *shell = [self firstExistingExecutable:@[
        [jbRoot stringByAppendingPathComponent:@"bin/sh"],
        [jbRoot stringByAppendingPathComponent:@"usr/bin/sh"],
        [jbRoot stringByAppendingPathComponent:@"bin/bash"],
        [jbRoot stringByAppendingPathComponent:@"usr/bin/bash"]
    ]];
    if (shell.length) {
        return shell;
    }

    shell = [self stageHelperToJBTools:@"bash"];
    if (shell.length) {
        return shell;
    }

    shell = [self firstExistingExecutable:@[
        @"/bin/sh",
        @"/usr/bin/sh"
    ]];
    if (shell.length) {
        return shell;
    }

    shell = [self bundledHelperExecutable:@"bash"];
    if (shell.length) {
        return shell;
    }

    return [self firstExistingExecutable:@[[jbRoot stringByAppendingPathComponent:@"assets/tools/bash"]]];
}

- (NSString *)bundledHelperExecutable:(NSString *)name {
    if (!name.length) return nil;
    NSString *assetsTools = [[[NSBundle mainBundle] resourcePath] stringByAppendingPathComponent:@"assets/tools"];
    NSString *candidate = [assetsTools stringByAppendingPathComponent:name];
    if ([[NSFileManager defaultManager] fileExistsAtPath:candidate]) {
        return candidate;
    }
    NSString *direct = [[[NSBundle mainBundle] resourcePath] stringByAppendingPathComponent:name];
    if ([[NSFileManager defaultManager] fileExistsAtPath:direct]) {
        return direct;
    }
    return nil;
}

- (NSString *)bootstrapHelperExecutableForNames:(NSArray<NSString *> *)names {
    for (NSString *name in names) {
        NSString *staged = [self stageHelperToJBTools:name];
        if (staged.length) {
            return staged;
        }
    }

    for (NSString *name in names) {
        NSString *bundled = [self bundledHelperExecutable:name];
        if (bundled.length) {
            return bundled;
        }
    }

    return nil;
}

- (NSString *)stageHelperToJBTools:(NSString *)name {
    NSString *source = [self bundledHelperExecutable:name];
    if (!source.length) return nil;

    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *toolsDir = [lara_bootstrap_root() stringByAppendingPathComponent:@"assets/tools"];
    NSError *mkErr = nil;
    if (![fm fileExistsAtPath:toolsDir] && ![fm createDirectoryAtPath:toolsDir withIntermediateDirectories:YES attributes:nil error:&mkErr]) {
        [self prepareSandboxExtensionsForBootstrapPaths:@[lara_bootstrap_root(), toolsDir]];
        mkErr = nil;
        if (![fm fileExistsAtPath:toolsDir] && ![fm createDirectoryAtPath:toolsDir withIntermediateDirectories:YES attributes:nil error:&mkErr]) {
            // VFS fallback: chown parent directories to mobile (501) and retry
            if (vfs_isready() && [lara_bootstrap_root() isEqualToString:@"/var/mobile/jb"]) {
                [self appendCommandLog:@"[bootstrap] trying VFS mkdir fallback...\n"];
                if (vfs_mkdir_p("/var/mobile/jb/assets/tools", 501, 501) == 0) {
                    [self appendCommandLog:@"[bootstrap] VFS mkdir succeeded!\n"];
                    goto staged_ok;
                }
                [self appendCommandLog:@"[bootstrap] VFS mkdir also failed\n"];
            }
            [self appendCommandLog:[NSString stringWithFormat:@"[bootstrap] cannot create staged tools dir %@: %@\n", toolsDir, mkErr.localizedDescription ?: @"unknown error"]];
            return nil;
        }
    }
staged_ok:;

    NSString *target = [toolsDir stringByAppendingPathComponent:name];

    NSDictionary *srcAttrs = [fm attributesOfItemAtPath:source error:nil];
    NSDictionary *dstAttrs = [fm attributesOfItemAtPath:target error:nil];
    NSNumber *srcSize = srcAttrs[NSFileSize];
    NSNumber *dstSize = dstAttrs[NSFileSize];
    BOOL needsCopy = !(srcSize && dstSize && [srcSize isEqualToNumber:dstSize]);

    if (needsCopy) {
        [fm removeItemAtPath:target error:nil];
        NSError *copyErr = nil;
        if (![fm copyItemAtPath:source toPath:target error:&copyErr]) {
            [self appendCommandLog:[NSString stringWithFormat:@"[bootstrap] stage copy failed %@ -> %@: %@\n", source, target, copyErr.localizedDescription ?: @"unknown error"]];
            return nil;
        }
    }

    chmod(target.fileSystemRepresentation, 0755);
    [self prepareSandboxExtensionsForBootstrapPaths:@[lara_bootstrap_root(), toolsDir, target]];
    return target;
}

- (void)prepareSandboxExtensionsForBootstrapPaths:(NSArray<NSString *> *)paths {
    NSArray<NSString *> *classes = @[
        @"com.apple.app-sandbox.read-write",
        @"APP_SANDBOX_READ_WRITE",
        @"com.apple.app-sandbox.read",
        @"APP_SANDBOX_READ",
        @"com.apple.sandbox.executable"
    ];

    NSMutableOrderedSet<NSString *> *uniquePaths = [NSMutableOrderedSet orderedSet];
    for (NSString *path in paths) {
        if (path.length) [uniquePaths addObject:path];
    }

    NSArray<NSString *> *systemPaths = @[@"/bin", @"/bin/sh", @"/usr/bin", @"/usr/bin/tar", @"/usr/bin/bsdtar", @"/usr/bin/unzip"];
    for (NSString *path in systemPaths) {
        [uniquePaths addObject:path];
    }

    for (NSString *path in uniquePaths) {
        BOOL any = NO;
        for (NSString *extensionClass in classes) {
            BOOL ok = sbx_issue_and_consume_extension(extensionClass, path);
            [self appendCommandLog:[NSString stringWithFormat:@"[sandbox] class=%@ path=%@ result=%@\n", extensionClass, path, ok ? @"ok" : @"fail"]];
            any = any || ok;
        }
        if (!any) {
            [self appendCommandLog:[NSString stringWithFormat:@"[sandbox] no extension granted for %@\n", path]];
        }
    }
}

- (NSString *)aptBinaryDiagnostics {
    NSMutableString *s = [NSMutableString stringWithString:@"[apt-diag] probing key paths\n"];
    NSString *jbRoot = lara_bootstrap_root();
    NSArray<NSString *> *dpkgCandidates = lara_bootstrap_dpkg_status_candidates();
    NSArray<NSString *> *paths = @[
        jbRoot,
        [jbRoot stringByAppendingPathComponent:@"usr"],
        [jbRoot stringByAppendingPathComponent:@"usr/bin"],
        [jbRoot stringByAppendingPathComponent:@"usr/bin/apt-get"],
        @"/usr/bin/apt-get",
        dpkgCandidates.firstObject ?: @"",
        dpkgCandidates.lastObject ?: @""
    ];
    NSFileManager *fm = [NSFileManager defaultManager];
    for (NSString *p in paths) {
        BOOL exists = [fm fileExistsAtPath:p];
        BOOL isDir = NO;
        [fm fileExistsAtPath:p isDirectory:&isDir];
        [s appendFormat:@"[apt-diag] %@ exists=%@ dir=%@\n", p, exists ? @"yes" : @"no", isDir ? @"yes" : @"no"];
    }
    return s;
}

- (void)fixBootstrapPermissionsForRootless {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *bootstrapRoot = lara_bootstrap_root();
    NSString *mobileRoot = [bootstrapRoot stringByAppendingPathComponent:@"var/mobile"];
    if (![fm fileExistsAtPath:bootstrapRoot]) {
        [self appendCommandLog:[NSString stringWithFormat:@"[bootstrap:perm] skip: %@ does not exist\n", bootstrapRoot]];
        return;
    }

    NSMutableArray<NSString *> *paths = [NSMutableArray arrayWithObject:bootstrapRoot];
    if ([fm fileExistsAtPath:mobileRoot]) {
        [paths addObject:mobileRoot];
    }

    NSArray<NSString *> *seedRoots = @[bootstrapRoot, mobileRoot];
    for (NSString *seedRoot in seedRoots) {
        BOOL seedIsDir = NO;
        if (![fm fileExistsAtPath:seedRoot isDirectory:&seedIsDir] || !seedIsDir) {
            continue;
        }
        NSDirectoryEnumerator<NSString *> *enumerator = [fm enumeratorAtPath:seedRoot];
        for (NSString *rel in enumerator) {
            if (!rel.length) continue;
            [paths addObject:[seedRoot stringByAppendingPathComponent:rel]];
        }
    }

    NSUInteger ownerOk = 0;
    NSUInteger ownerFail = 0;
    NSUInteger dirModeOk = 0;
    NSUInteger dirModeFail = 0;

    // Explicit key paths first to mirror Dopamine-style ownership normalization.
    NSArray<NSString *> *keyDirs = @[
        bootstrapRoot,
        [bootstrapRoot stringByAppendingPathComponent:@"var"],
        mobileRoot,
        [mobileRoot stringByAppendingPathComponent:@"Library"],
        [mobileRoot stringByAppendingPathComponent:@"Library/Preferences"],
        [mobileRoot stringByAppendingPathComponent:@"Library/Caches"]
    ];
    for (NSString *keyDir in keyDirs) {
        BOOL isDir = NO;
        if (![fm fileExistsAtPath:keyDir isDirectory:&isDir] || !isDir) {
            continue;
        }

        errno = 0;
        int ownRc = lchown(keyDir.fileSystemRepresentation, 501, 501);
        if (ownRc == 0) {
            ownerOk++;
        } else {
            ownerFail++;
        }

        errno = 0;
        int modRc = chmod(keyDir.fileSystemRepresentation, 0755);
        if (modRc == 0) {
            dirModeOk++;
        } else {
            dirModeFail++;
        }
    }

    for (NSString *path in paths) {
        errno = 0;
        int ownRc = lchown(path.fileSystemRepresentation, 501, 501);
        if (ownRc == 0) {
            ownerOk++;
        } else {
            ownerFail++;
        }

        struct stat st;
        if (lstat(path.fileSystemRepresentation, &st) == 0 && S_ISDIR(st.st_mode)) {
            errno = 0;
            int modRc = chmod(path.fileSystemRepresentation, 0755);
            if (modRc == 0) {
                dirModeOk++;
            } else {
                dirModeFail++;
            }
        }
    }

    [self appendCommandLog:[NSString stringWithFormat:@"[bootstrap:perm] recursive bootstrap_root=%@ mobile_root=%@ entries=%lu chown_ok=%lu chown_fail=%lu dir_chmod_ok=%lu dir_chmod_fail=%lu\n", bootstrapRoot, mobileRoot, (unsigned long)paths.count, (unsigned long)ownerOk, (unsigned long)ownerFail, (unsigned long)dirModeOk, (unsigned long)dirModeFail]];
}

- (BOOL)ensureDefaultSourcesConfigured:(NSError **)err {
    NSString *sourcesDir = [lara_bootstrap_root() stringByAppendingPathComponent:@"etc/apt/sources.list.d"];
    if (!_sileo_ensure_directory(sourcesDir, err)) {
        return NO;
    }

    NSString *defaultSourcesPath = [sourcesDir stringByAppendingPathComponent:@"default.sources"];
    NSString *defaultSources =
        @"Types: deb\n"
        @"URIs: https://repo.chariz.com/\n"
        @"Suites: ./\n"
        @"Components:\n"
        @"\n"
        @"Types: deb\n"
        @"URIs: https://havoc.app/\n"
        @"Suites: ./\n"
        @"Components:\n"
        @"\n"
        @"Types: deb\n"
        @"URIs: http://apt.thebigboss.org/repofiles/cydia/\n"
        @"Suites: stable\n"
        @"Components: main\n"
        @"\n"
        @"Types: deb\n"
        @"URIs: https://ellekit.space/\n"
        @"Suites: ./\n"
        @"Components:\n";

    if (![defaultSources writeToFile:defaultSourcesPath atomically:NO encoding:NSUTF8StringEncoding error:err]) {
        return NO;
    }

    [self appendCommandLog:@"[repo] default sources configured (chariz/havoc/bigboss/ellekit)\n"];
    return YES;
}

- (NSString *)dopamineBootstrapVersion {
    uint64_t cfver = (((uint64_t)kCFCoreFoundationVersionNumber / 100) * 100);
    if (cfver >= 2000) {
        return nil;
    }
    return [NSString stringWithFormat:@"%llu", cfver];
}

- (BOOL)ensureSileoRepoConfigured:(NSError **)err {
    NSString *sourcesDir = [lara_bootstrap_root() stringByAppendingPathComponent:@"etc/apt/sources.list.d"];
    if (!_sileo_ensure_directory(sourcesDir, err)) {
        return NO;
    }

    NSString *sileoList = [sourcesDir stringByAppendingPathComponent:@"sileo.sources"];
    NSString *content = [NSString stringWithFormat:@"Types: deb\nURIs: %@\nSuites: ./\nComponents:\n", kSileoRepoURL];
    if (![content writeToFile:sileoList atomically:NO encoding:NSUTF8StringEncoding error:err]) {
        return NO;
    }
    return YES;
}

- (NSTimeInterval)timeoutForCommandArgs:(NSArray<NSString *> *)args {
    if (args.count >= 2) {
        NSString *subcommand = args[1] ?: @"";
        if ([subcommand isEqualToString:@"install"]) {
            return 900.0;
        }
        if ([subcommand isEqualToString:@"update"]) {
            return 300.0;
        }
    }

    NSString *commandLine = [args componentsJoinedByString:@" "];
    if ([commandLine containsString:@"prep_bootstrap.sh"]) {
        return 300.0;
    }
    if ([commandLine containsString:@" -xf "] ||
        [commandLine containsString:@"bsdtar"] ||
        [commandLine containsString:@"tar-procursus"] ||
        [commandLine containsString:@"--use-compress-program"] ||
        [commandLine containsString:@" -I "]) {
        return 300.0;
    }

    return 60.0;
}

- (int)runCommand:(NSArray<NSString *> *)args output:(NSString **)outStr {
    if (args.count == 0) {
        if (outStr) *outStr = @"No command";
        return -1;
    }

    const char *cmd = args[0].UTF8String;

    int pipefd[2] = {-1, -1};
    if (pipe(pipefd) != 0) {
        if (outStr) *outStr = @"pipe() failed";
        return -3;
    }

    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions, pipefd[1], STDOUT_FILENO);
    posix_spawn_file_actions_adddup2(&actions, pipefd[1], STDERR_FILENO);
    posix_spawn_file_actions_addclose(&actions, pipefd[0]);

    size_t argc = args.count;
    char **argv = (char **)calloc(argc + 1, sizeof(char *));
    for (size_t i = 0; i < argc; i++) {
        argv[i] = (char *)args[i].UTF8String;
    }
    argv[argc] = NULL;

    char *dyldPath = NULL;
    char *dyldFallback = NULL;
    NSString *homePath = (getuid() == 0) ? [lara_bootstrap_root() stringByAppendingPathComponent:@"root"] : @"/var/mobile";
    NSString *homeEnvStr = [NSString stringWithFormat:@"HOME=%@", homePath];
    char *homeEnv = strdup(homeEnvStr.UTF8String);
    char *tmpEnv = strdup("TMPDIR=/var/tmp");
    char *localeEnv = strdup("LC_ALL=C.UTF-8");
    NSString *commandPath = args.firstObject;
    if ([commandPath containsString:@"/assets/tools/"] || [commandPath containsString:@"/var/mobile/jb/assets/tools/"]) {
        NSString *helperDir = [commandPath stringByDeletingLastPathComponent];
        NSString *dyldPathStr = [NSString stringWithFormat:@"DYLD_LIBRARY_PATH=%@", helperDir];
        NSString *dyldFallbackStr = [NSString stringWithFormat:@"DYLD_FALLBACK_LIBRARY_PATH=%@:/usr/lib:/System/Library/Frameworks", helperDir];
        dyldPath = strdup(dyldPathStr.UTF8String);
        dyldFallback = strdup(dyldFallbackStr.UTF8String);
    }

    NSString *jbRoot = lara_bootstrap_root();
    NSString *pathEnvStr = [NSString stringWithFormat:@"PATH=%@/usr/bin:%@/bin:/usr/bin:/bin", jbRoot, jbRoot];
    // Простой вариант: /var/mobile/jb/usr/bin и /var/mobile/jb/bin, затем системные.
    char *pathEnv = strdup(pathEnvStr.UTF8String);

    NSString *locPathStr = [NSString stringWithFormat:@"LOCPATH=%@", [lara_bootstrap_root() stringByAppendingPathComponent:@"usr/share/locale"]];
    char *locPathEnv = strdup(locPathStr.UTF8String);

    char *envp[] = {
        pathEnv,
        "DEBIAN_FRONTEND=noninteractive",
        homeEnv,
        tmpEnv,
        locPathEnv,
        localeEnv,
        dyldPath,
        dyldFallback,
        NULL
    };

    static BOOL loggedSpawnEnv = NO;
    if (!loggedSpawnEnv) {
        [self appendCommandLog:[NSString stringWithFormat:@"[spawn:env] uid=%d HOME=%@ PATH=%@ LOCPATH=%@ LC_ALL=C.UTF-8\n",
                                getuid(), homePath, pathEnvStr, locPathStr]];
        loggedSpawnEnv = YES;
    }

    NSString *lowerCommandPath = [commandPath.lowercaseString copy] ?: @"";
    BOOL rootPersonaFirst = getuid() != 0 &&
        ([lowerCommandPath hasSuffix:@"/mkdir"] ||
         [lowerCommandPath hasSuffix:@"/chmod"] ||
         [lowerCommandPath hasSuffix:@"/chown"]);

    pid_t pid = 0;
    int spawnErr = EPERM;
    if (rootPersonaFirst) {
        NSString *personaDiag = nil;
        int personaErr = _sileo_spawn_with_root_persona(&pid, cmd, &actions, argv, envp, &personaDiag);
        [self appendCommandLog:[NSString stringWithFormat:@"[command] root persona first for %s => %d (%@)\n",
                                cmd,
                                personaErr,
                                personaDiag ?: @"no diag"]];
        if (personaErr == 0) {
            spawnErr = 0;
        } else {
            spawnErr = posix_spawn(&pid, cmd, &actions, NULL, argv, envp);
        }
    } else {
        spawnErr = posix_spawn(&pid, cmd, &actions, NULL, argv, envp);
    }

    BOOL rootPersonaCandidate = !rootPersonaFirst && _sileo_should_try_root_persona_fallback(cmd, args);
    if (spawnErr == EPERM && rootPersonaCandidate) {
        NSString *personaDiag = nil;
        int personaErr = _sileo_spawn_with_root_persona(&pid, cmd, &actions, argv, envp, &personaDiag);
        [self appendCommandLog:[NSString stringWithFormat:@"[command] root persona fallback for %s => %d (%@)\n", cmd, personaErr, personaDiag ?: @"no diag"]];
        if (personaErr == 0) {
            spawnErr = 0;
        }
    } else if (spawnErr == EPERM && getuid() != 0) {
        [self appendCommandLog:[NSString stringWithFormat:@"[command] root persona fallback skipped for %s (candidate=%@)\n", cmd, rootPersonaCandidate ? @"yes" : @"no"]];
    }
    if (spawnErr == EPERM && getuid() != 0) {
        sbx_setlogcallback(_sileo_sbx_log);
        uint64_t ourProc = ds_get_our_proc();
        if (ourProc != 0) {
            int escRc = sbx_escape(ourProc);
            uid_t uidNow = getuid();
            gid_t gidNow = getgid();
            [self appendCommandLog:[NSString stringWithFormat:@"[command] posix_spawn EPERM for %s, retrying after sbx_escape only rc=%d uid=%d gid=%d\n", cmd, escRc, uidNow, gidNow]];
            spawnErr = posix_spawn(&pid, cmd, &actions, NULL, argv, envp);
            if (spawnErr == EPERM) {
                int escRc2 = sbx_escape(ourProc);
                uid_t uidNow2 = getuid();
                gid_t gidNow2 = getgid();
                [self appendCommandLog:[NSString stringWithFormat:@"[command] second EPERM for %s after sbx_escape-only retry rc=%d uid=%d gid=%d\n", cmd, escRc2, uidNow2, gidNow2]];
                spawnErr = posix_spawn(&pid, cmd, &actions, NULL, argv, envp);
            }
        }
    }

    if (dyldPath) free(dyldPath);
    if (dyldFallback) free(dyldFallback);
    if (localeEnv) free(localeEnv);
    if (homeEnv) free(homeEnv);
    if (tmpEnv) free(tmpEnv);
    free(argv);
    posix_spawn_file_actions_destroy(&actions);
    close(pipefd[1]);

    if (spawnErr != 0) {
        close(pipefd[0]);
        if (outStr) {
            *outStr = [NSString stringWithFormat:@"posix_spawn failed: %d (%s), uid=%d gid=%d cmd=%s", spawnErr, strerror(spawnErr), getuid(), getgid(), cmd];
        }
        return spawnErr;
    }

    int flags = fcntl(pipefd[0], F_GETFL, 0);
    if (flags != -1) {
        fcntl(pipefd[0], F_SETFL, flags | O_NONBLOCK);
    }

    NSMutableData *captured = [NSMutableData data];
    uint8_t buf[4096];
    int status = 0;
    BOOL didExit = NO;
    BOOL sawEOF = NO;
    BOOL timedOut = NO;
    CFAbsoluteTime startedAt = CFAbsoluteTimeGetCurrent();
    NSTimeInterval timeout = [self timeoutForCommandArgs:args];

    while (true) {
        ssize_t n = 0;
        while ((n = read(pipefd[0], buf, sizeof(buf))) > 0) {
            [captured appendBytes:buf length:(NSUInteger)n];
        }

        if (n == 0) {
            sawEOF = YES;
        }

        if (!didExit) {
            pid_t waitRc = waitpid(pid, &status, WNOHANG);
            if (waitRc == pid) {
                didExit = YES;
            }
        }

        if (!didExit && timeout > 0 && (CFAbsoluteTimeGetCurrent() - startedAt) > timeout) {
            timedOut = YES;
            kill(pid, SIGTERM);
            usleep(200000);
            if (waitpid(pid, &status, WNOHANG) == 0) {
                kill(pid, SIGKILL);
            }
            waitpid(pid, &status, 0);
            didExit = YES;
            while ((n = read(pipefd[0], buf, sizeof(buf))) > 0) {
                [captured appendBytes:buf length:(NSUInteger)n];
            }
            break;
        }

        if (didExit && sawEOF) {
            break;
        }

        usleep(100000);
    }

    close(pipefd[0]);

    NSString *txt = [[NSString alloc] initWithData:captured encoding:NSUTF8StringEncoding] ?: @"";
    if (timedOut) {
        NSString *timeoutText = [NSString stringWithFormat:@"%@%@\n[timeout] command exceeded %.0f seconds\n", txt, txt.length ? @"" : @"(no output)", timeout];
        if (outStr) *outStr = timeoutText;
        [self appendCommandLog:[NSString stringWithFormat:@"[command] timeout after %.0fs: %@\n", timeout, [args componentsJoinedByString:@" "]]];
        return -9;
    }

    if (outStr) *outStr = txt;

    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return -4;
}

- (void)preparePersistentLogFile {
    NSArray<NSString *> *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *documentsPath = docs.firstObject ?: NSTemporaryDirectory();
    self.logFilePath = [documentsPath stringByAppendingPathComponent:@"lara.log"];

    NSString *header = [NSString stringWithFormat:@"\n\n==== Sileo installer session %@ ====\n",
                        [NSDate date]];
    [self appendTextToPersistentLogFile:header];
}

- (void)appendTextToPersistentLogFile:(NSString *)text {
    if (!text.length) return;
    if (!self.logFilePath.length) return;

    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:self.logFilePath]) {
        [text writeToFile:self.logFilePath atomically:YES encoding:NSUTF8StringEncoding error:nil];
        return;
    }

    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:self.logFilePath];
    if (!fh) return;
    @try {
        [fh seekToEndOfFile];
        NSData *d = [text dataUsingEncoding:NSUTF8StringEncoding];
        [fh writeData:d];
    } @catch (__unused NSException *e) {
    } @finally {
        [fh closeFile];
    }
}

- (void)resetCommandLog {
    self.commandLog = [NSMutableString string];
    self.logView.text = @"";
    [self appendTextToPersistentLogFile:@"[session] reset in-app log buffer\n"];
    [self appendCommandLog:[NSString stringWithFormat:@"[runtime] Sileo installer build=%@\n", kInstallerRuntimeTag]];
}

- (void)appendCommandLog:(NSString *)chunk {
    if (!chunk) return;
    [self appendTextToPersistentLogFile:chunk];
    [[Logger shared] log:chunk];
    dispatch_async(dispatch_get_main_queue(), ^{
        if (!self.commandLog) self.commandLog = [NSMutableString string];
        [self.commandLog appendString:chunk];
        self.logView.text = self.commandLog;
        if (self.logView.text.length > 0) {
            NSRange bottom = NSMakeRange(self.logView.text.length - 1, 1);
            [self.logView scrollRangeToVisible:bottom];
        }
    });
}

- (void)appendCommandOutputForCommand:(NSString *)command output:(NSString *)output exitCode:(int)exitCode {
    NSMutableString *block = [NSMutableString stringWithFormat:@"\n$ %@\n", command ?: @"(command)"];
    if (output.length) {
        [block appendString:output];
        if (![output hasSuffix:@"\n"]) {
            [block appendString:@"\n"];
        }
    } else {
        [block appendString:@"(no output)\n"];
    }
    [block appendFormat:@"[exit] %d\n", exitCode];
    [self appendCommandLog:block];
}

- (NSString *)firstExistingExecutable:(NSArray<NSString *> *)candidates {
    NSFileManager *fm = [NSFileManager defaultManager];
    for (NSString *path in candidates) {
        BOOL isDir = NO;
        if ([fm fileExistsAtPath:path isDirectory:&isDir] && !isDir) {
            return path;
        }
    }
    return nil;
}

// ── Helper: offer respring ────────────────────────────────────────────────────

- (void)offerRespring {
    UIAlertController *a = [UIAlertController
        alertControllerWithTitle:@"Installation Complete"
                         message:@"Sileo has been installed. Respring now to apply?"
                  preferredStyle:UIAlertControllerStyleAlert];
    [a addAction:[UIAlertAction actionWithTitle:@"Respring" style:UIAlertActionStyleDestructive
                                        handler:^(UIAlertAction *_) {
        [UIApplication.sharedApplication performSelector:@selector(suspend)];
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            exit(0); // trigger SpringBoard relaunch if running with jailbreak daemon
        });
    }]];
    [a addAction:[UIAlertAction actionWithTitle:@"Later" style:UIAlertActionStyleCancel handler:nil]];
    [self presentViewController:a animated:YES completion:nil];
}

// ── UI state helpers ──────────────────────────────────────────────────────────

- (void)setState:(InstallerState)s status:(NSString *)msg {
    if (![NSThread isMainThread]) {
        dispatch_async(dispatch_get_main_queue(), ^{
            [self setState:s status:msg];
        });
        return;
    }

    self.state = s;
    self.statusLabel.text = msg;
    NSString *line = [NSString stringWithFormat:@"[state:%ld] %@", (long)s, msg ?: @"(no status)"];
    [self appendTextToPersistentLogFile:[line stringByAppendingString:@"\n"]];
    [[Logger shared] enclosedLog:line];

    BOOL busy = (s == InstallerStateFetching ||
                 s == InstallerStateInstalling);

    [UIView animateWithDuration:0.25 animations:^{
        self.progressBar.alpha = busy ? 1.0 : 0.0;
    }];

    self.installButton.enabled = !busy;
    self.installButton.alpha   = busy ? 0.5 : 1.0;
    self.navigationItem.hidesBackButton = busy;

    if (s == InstallerStateError) {
        [self.installButton setTitle:@"Retry" forState:UIControlStateNormal];
        self.installButton.backgroundColor = UIColor.systemRedColor;
    } else if (s == InstallerStateDone) {
        [self.installButton setTitle:@"Done" forState:UIControlStateNormal];
        self.installButton.backgroundColor = UIColor.systemGreenColor;
    } else {
        [self.installButton setTitle:@"Install" forState:UIControlStateNormal];
        self.installButton.backgroundColor = UIColor.systemIndigoColor;
    }
}

- (void)setProgress:(float)p status:(NSString *)msg {
    if (![NSThread isMainThread]) {
        dispatch_async(dispatch_get_main_queue(), ^{
            [self setProgress:p status:msg];
        });
        return;
    }

    self.statusLabel.text = msg;
    [self.progressBar setProgress:p animated:YES];
    NSString *line = [NSString stringWithFormat:@"[progress %.0f%%] %@", p * 100.0f, msg ?: @"(no status)"];
    [self appendTextToPersistentLogFile:[line stringByAppendingString:@"\n"]];
    [[Logger shared] log:line];
}

@end
