//
//  ZeroViewController.m
//  lara
//
//  Rewritten in Objective-C (was ZeroView.swift)
//

#import "ZeroViewController.h"
#import "../LaraManager.h"

// Mirrors ZeroView.swift tweak list
static NSArray<NSDictionary *> *allTweaks(void) {
    static NSArray *arr;
    static dispatch_once_t t;
    dispatch_once(&t, ^{
        arr = @[
            @{@"name": @"Hide Dock Background",         @"paths": @[@"/System/Library/PrivateFrameworks/CoreMaterial.framework/dockDark.materialrecipe", @"/System/Library/PrivateFrameworks/CoreMaterial.framework/dockLight.materialrecipe"]},
            @{@"name": @"Clear Folder Backgrounds",      @"paths": @[@"/System/Library/PrivateFrameworks/SpringBoardHome.framework/folderDark.materialrecipe", @"/System/Library/PrivateFrameworks/SpringBoardHome.framework/folderLight.materialrecipe"]},
            @{@"name": @"Clear Widget Config BG",        @"paths": @[@"/System/Library/PrivateFrameworks/SpringBoardHome.framework/stackConfigurationBackground.materialrecipe", @"/System/Library/PrivateFrameworks/SpringBoardHome.framework/stackConfigurationForeground.materialrecipe"]},
            @{@"name": @"Clear App Library BG",          @"paths": @[@"/System/Library/PrivateFrameworks/SpringBoardHome.framework/coplanarLeadingTrailingBackgroundBlur.materialrecipe"]},
            @{@"name": @"Clear Library Search BG",       @"paths": @[@"/System/Library/PrivateFrameworks/SpringBoardHome.framework/homeScreenOverlay.materialrecipe"]},
            @{@"name": @"Clear Spotlight Background",    @"paths": @[@"/System/Library/PrivateFrameworks/SpringBoardHome.framework/knowledgeBackgroundDarkZoomed.descendantrecipe", @"/System/Library/PrivateFrameworks/SpringBoardHome.framework/knowledgeBackgroundZoomed.descendantrecipe"]},
            @{@"name": @"Hide Delete Icon",              @"paths": @[@"/System/Library/PrivateFrameworks/SpringBoardHome.framework/Assets.car"]},
            @{@"name": @"Clear Passcode Background",     @"paths": @[@"/System/Library/PrivateFrameworks/CoverSheet.framework/dashBoardPasscodeBackground.materialrecipe"]},
            @{@"name": @"Hide Lock Icon",                @"paths": @[@"/System/Library/PrivateFrameworks/SpringBoardUIServices.framework/lock@2x-812h.ca/main.caml", @"/System/Library/PrivateFrameworks/SpringBoardUIServices.framework/lock@2x-896h.ca/main.caml", @"/System/Library/PrivateFrameworks/SpringBoardUIServices.framework/lock@3x-812h.ca/main.caml", @"/System/Library/PrivateFrameworks/SpringBoardUIServices.framework/lock@3x-896h.ca/main.caml", @"/System/Library/PrivateFrameworks/SpringBoardUIServices.framework/lock@3x-d73.ca/main.caml"]},
            @{@"name": @"Hide Quick Action Icons",       @"paths": @[@"/System/Library/PrivateFrameworks/CoverSheet.framework/Assets.car"]},
            @{@"name": @"Hide Large Battery Icon",       @"paths": @[@"/System/Library/PrivateFrameworks/CoverSheet.framework/Assets.car"]},
            @{@"name": @"Clear Notification & Widget BGs", @"paths": @[@"/System/Library/PrivateFrameworks/CoreMaterial.framework/platterStrokeLight.visualstyleset", @"/System/Library/PrivateFrameworks/CoreMaterial.framework/platterStrokeDark.visualstyleset", @"/System/Library/PrivateFrameworks/CoreMaterial.framework/plattersDark.materialrecipe", @"/System/Library/PrivateFrameworks/CoreMaterial.framework/platters.materialrecipe", @"/System/Library/PrivateFrameworks/UserNotificationsUIKit.framework/stackDimmingLight.visualstyleset", @"/System/Library/PrivateFrameworks/UserNotificationsUIKit.framework/stackDimmingDark.visualstyleset"]},
            @{@"name": @"Blue Notification Shadows",     @"paths": @[@"/System/Library/PrivateFrameworks/PlatterKit.framework/platterVibrantShadowLight.visualstyleset", @"/System/Library/PrivateFrameworks/PlatterKit.framework/platterVibrantShadowDark.visualstyleset"]},
            @{@"name": @"Clear Touch & Alert Backgrounds", @"paths": @[@"/System/Library/PrivateFrameworks/CoreMaterial.framework/platformContentDark.materialrecipe", @"/System/Library/PrivateFrameworks/CoreMaterial.framework/platformContentLight.materialrecipe"]},
            @{@"name": @"Hide Home Bar",                 @"paths": @[@"/System/Library/PrivateFrameworks/MaterialKit.framework/Assets.car"]},
            @{@"name": @"Remove Glassy Overlays",        @"paths": @[@"/System/Library/PrivateFrameworks/CoreMaterial.framework/platformChromeDark.materialrecipe", @"/System/Library/PrivateFrameworks/CoreMaterial.framework/platformChromeLight.materialrecipe"]},
            @{@"name": @"Clear App Switcher",            @"paths": @[@"/System/Library/PrivateFrameworks/SpringBoard.framework/homeScreenBackdrop-application.materialrecipe", @"/System/Library/PrivateFrameworks/SpringBoard.framework/homeScreenBackdrop-switcher.materialrecipe"]},
            @{@"name": @"Enable Helvetica Font",         @"paths": @[@"/System/Library/Fonts/Core/SFUI.ttf"]},
            @{@"name": @"Enable Helvetica Font (CoreUI)", @"paths": @[@"/System/Library/Fonts/CoreUI/SFUI.ttf"]},
            @{@"name": @"Disable Emojis",                @"paths": @[@"/System/Library/Fonts/CoreAddition/AppleColorEmoji-160px.ttc"]},
            @{@"name": @"Hide Ringer Icon",              @"paths": @[@"/System/Library/PrivateFrameworks/SpringBoard.framework/Ringer-Leading-D73.ca/main.caml"]},
            @{@"name": @"Hide Tethering Icon",           @"paths": @[@"/System/Library/PrivateFrameworks/SpringBoard.framework/Tethering-D73.ca/main.caml"]},
            @{@"name": @"Clear CC Modules",              @"paths": @[@"/System/Library/PrivateFrameworks/CoreMaterial.framework/modulesSheer.descendantrecipe", @"/System/Library/ControlCenter/Bundles/FocusUIModule.bundle/Info.plist"]},
            @{@"name": @"Disable Slider Icons",          @"paths": @[@"/System/Library/ControlCenter/Bundles/DisplayModule.bundle/Brightness.ca/index.xml", @"/System/Library/PrivateFrameworks/MediaControls.framework/VolumeSemibold.ca/index.xml"]},
            @{@"name": @"Hide Player Buttons",           @"paths": @[@"/System/Library/PrivateFrameworks/MediaControls.framework/PlayPauseStop.ca/index.xml", @"/System/Library/PrivateFrameworks/MediaControls.framework/ForwardBackward.ca/index.xml"]},
            @{@"name": @"Hide DND Icon",                 @"paths": @[@"/System/Library/PrivateFrameworks/FocusUI.framework/dnd_cg_02.ca/main.caml"]},
            @{@"name": @"Hide WiFi & Bluetooth Icons",   @"paths": @[@"/System/Library/ControlCenter/Bundles/ConnectivityModule.bundle/Bluetooth.ca/index.xml", @"/System/Library/ControlCenter/Bundles/ConnectivityModule.bundle/WiFi.ca/index.xml"]},
            @{@"name": @"Disable Screen Mirroring Module", @"paths": @[@"/System/Library/ControlCenter/Bundles/AirPlayMirroringModule.bundle/Info.plist"]},
            @{@"name": @"Disable Orientation Lock Module", @"paths": @[@"/System/Library/ControlCenter/Bundles/OrientationLockModule.bundle/Info.plist"]},
            @{@"name": @"Disable Focus Module",          @"paths": @[@"/System/Library/ControlCenter/Bundles/FocusUIModule.bundle/Info.plist"]},
            @{@"name": @"Disable AirDrop Ping",          @"paths": @[@"/System/Library/Audio/UISounds/Modern/airdrop_invite.cat"]},
            @{@"name": @"Disable Charge Sound",          @"paths": @[@"/System/Library/Audio/UISounds/connect_power.caf"]},
            @{@"name": @"Disable Low Battery Sound",     @"paths": @[@"/System/Library/Audio/UISounds/low_power.caf"]},
            @{@"name": @"Disable Payment Sounds",        @"paths": @[@"/System/Library/Audio/UISounds/payment_success.caf", @"/System/Library/Audio/UISounds/payment_failure.caf"]},
            @{@"name": @"Remove CC Background",          @"paths": @[@"/System/Library/PrivateFrameworks/CoreMaterial.framework/modulesBackground.materialrecipe"]},
            @{@"name": @"Disable ALL Banners",           @"paths": @[@"/System/Library/PrivateFrameworks/SpringBoard.framework/BannersAuthorizedBundleIDs.plist"]},
            @{@"name": @"Break System Font",             @"paths": @[@"/System/Library/Fonts/Core/SFUI.ttf", @"/System/Library/Fonts/Core/Helvetica.ttc"]},
            @{@"name": @"Break Clock Font",              @"paths": @[@"/System/Library/Fonts/Core/ADTNumeric.ttc"]},
        ];
    });
    return arr;
}

@interface ZeroViewController ()
@property (nonatomic, strong) LaraManager *mgr;
@property (nonatomic, strong) NSMutableSet<NSString *> *selected;
@end

@implementation ZeroViewController

- (instancetype)initWithMgr:(LaraManager *)mgr {
    self = [super initWithStyle:UITableViewStyleInsetGrouped];
    if (self) {
        _mgr = mgr;
        _selected = [NSMutableSet set];
        [self loadSelected];
    }
    return self;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"DirtyZero";

    UIBarButtonItem *applyBtn = [[UIBarButtonItem alloc]
        initWithTitle:@"Apply"
                style:UIBarButtonItemStyleDone
               target:self
               action:@selector(applySelected)];
    self.navigationItem.rightBarButtonItem = applyBtn;
}

- (void)loadSelected {
    NSData *data = [[NSUserDefaults standardUserDefaults] dataForKey:@"selecteddata"];
    if (!data) return;
    NSArray *arr = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
    if ([arr isKindOfClass:[NSArray class]]) {
        [self.selected addObjectsFromArray:arr];
    }
}

- (void)saveSelected {
    NSData *data = [NSJSONSerialization dataWithJSONObject:self.selected.allObjects options:0 error:nil];
    [[NSUserDefaults standardUserDefaults] setObject:data forKey:@"selecteddata"];
}

- (NSString *)tweakId:(NSDictionary *)tweak {
    NSArray *paths = tweak[@"paths"];
    return [NSString stringWithFormat:@"%@|%@", tweak[@"name"], [paths componentsJoinedByString:@"|"]];
}

- (void)applySelected {
    NSArray *tweaks = allTweaks();
    for (NSDictionary *tweak in tweaks) {
        NSString *tid = [self tweakId:tweak];
        if ([self.selected containsObject:tid]) {
            for (NSString *path in tweak[@"paths"]) {
                [self.mgr vfsZeroPage:path];
            }
        }
    }
}

#pragma mark - Table View

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView { return 1; }

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    return (NSInteger)allTweaks().count;
}

- (NSString *)tableView:(UITableView *)tableView titleForFooterInSection:(NSInteger)section {
    return @"Big thanks to jailbreak.party!\nNOTE: Many tweaks may not work currently.";
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:nil];
    NSDictionary *tweak = allTweaks()[indexPath.row];
    cell.textLabel.text = tweak[@"name"];
    NSString *tid = [self tweakId:tweak];
    cell.accessoryType = [self.selected containsObject:tid]
        ? UITableViewCellAccessoryCheckmark
        : UITableViewCellAccessoryNone;
    return cell;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    NSDictionary *tweak = allTweaks()[indexPath.row];
    NSString *tid = [self tweakId:tweak];
    if ([self.selected containsObject:tid]) {
        [self.selected removeObject:tid];
    } else {
        [self.selected addObject:tid];
    }
    [self saveSelected];
    [tableView reloadRowsAtIndexPaths:@[indexPath] withRowAnimation:UITableViewRowAnimationNone];
}

@end
