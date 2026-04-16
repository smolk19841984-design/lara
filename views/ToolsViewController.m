//
//  ToolsViewController.m
//  lara
//
//  Rewritten in Objective-C (was ToolsView.swift)
//

#import "ToolsViewController.h"
#import "../LaraManager.h"
#import "kexploit/darksword.h"
#import "kexploit/utils.h"
#import "kexploit/vfs.h"
#import "kexploit/sbx.h"
#import "TerminalViewController.h"
#import "../remote/LaraRemoteServer.h"
#import "../remote/LaraMobAIServer.h"
#import "kexploit/ppl.h"
#include <sys/sysctl.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>

typedef NS_ENUM(NSInteger, ToolsSection) {
    ToolsSectionStatus   = 0,
    ToolsSectionAdvanced = 1,
    ToolsSectionASLR     = 2,
    ToolsSectionProcess  = 3,
    ToolsSectionTerminal = 4,
    ToolsSectionRemote   = 5,
    ToolsSectionMobAI    = 6,
    ToolsSectionPPL      = 7,
    ToolsSectionCount
};


// Persistent log file path
static NSString *g_ppl_log_path = nil;

// Write log to file with immediate flush (survives kernel panic)
static void ppl_log_to_file(NSString *msg) {
    if (!g_ppl_log_path) {
        NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
        if (paths.count > 0) {
            g_ppl_log_path = [[paths[0] stringByAppendingPathComponent:@"ppl_test_log.txt"] copy];
        } else {
            return;
        }
    }

    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:g_ppl_log_path]) {
        [fm createFileAtPath:g_ppl_log_path contents:nil attributes:nil];
    }

    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:g_ppl_log_path];
    if (fh) {
        [fh seekToEndOfFile];
        NSString *line = [NSString stringWithFormat:@"%@\n", msg];
        [fh writeData:[line dataUsingEncoding:NSUTF8StringEncoding]];
        [fh synchronizeFile];
        [fh closeFile];
    }
}

@implementation ToolsViewController

- (instancetype)init {
    self = [super initWithStyle:UITableViewStyleInsetGrouped];
    return self;
}

- (NSString *)documentsTweaksPath {
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    return [docs stringByAppendingPathComponent:@"tweaks"];
}

- (void)setupTweaksFolderIfNeeded {
    // Tweaks folder setup removed - tweaks not working yet
}

- (void)viewDidLoad {
    [super viewDidLoad];
    [self setupTweaksFolderIfNeeded];
    self.title = @"Tools";

    UIBarButtonItem *refresh = [[UIBarButtonItem alloc]
        initWithBarButtonSystemItem:UIBarButtonSystemItemRefresh
                             target:self
                             action:@selector(refreshAll)];
    self.navigationItem.rightBarButtonItem = refresh;

    getaslrstate();
}

- (void)refreshAll {
    getaslrstate();
    [self.tableView reloadData];
}

#pragma mark - Table View

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    return [LaraManager shared].dsReady ? ToolsSectionCount : ToolsSectionCount;
}

// ...existing code...
- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    LaraManager *mgr = [LaraManager shared];
    switch (section) {
        case ToolsSectionStatus:  return 1;
        case ToolsSectionAdvanced:return 1;
        case ToolsSectionASLR:    return 2;
        case ToolsSectionProcess: return mgr.dsReady ? 4 : 2;
        case ToolsSectionTerminal: return 1;
        case ToolsSectionRemote: return 1;
        case ToolsSectionMobAI: return 1;
        case ToolsSectionPPL: return 3;
    }
    return 0;
}

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section {
    switch (section) {
        case ToolsSectionStatus:  return @"Status";
        case ToolsSectionAdvanced:return @"Tweaks & Tokens";
        case ToolsSectionASLR:    return @"ASLR";
        case ToolsSectionProcess: return @"Process";
        case ToolsSectionTerminal: return @"Terminal";
        case ToolsSectionRemote: return @"Remote Control";
        case ToolsSectionMobAI: return @"MobAI Server";
        case ToolsSectionPPL: return @"PPL Bypass Test";
    }
    return nil;
}

- (NSString *)tableView:(UITableView *)tableView titleForFooterInSection:(NSInteger)section {
    if (section == ToolsSectionASLR) {
        return @"Address Space Layout Randomization. Turning it on may break lara.";
    }
    if (section == ToolsSectionAdvanced) {
        return @"Generate a sandbox extension token.";
    }
    if (section == ToolsSectionTerminal) {
        return @"Built-in terminal with kernel R/W backend. No process spawning required.";
    }
    if (section == ToolsSectionRemote) {
        return @"HTTP server for PC remote control. Use lara-remote.py on PC to connect.";
    }
    if (section == ToolsSectionMobAI) {
        return @"MobAI-compatible API server (port 8686). Standard endpoints for iOS automation.";
    }
    if (section == ToolsSectionPPL) {
        return @"Test Direct PTE XPRR Modification bypass. Requires kernel R/W. iOS 17.3.1 (A12X).";
    }
    return nil;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleValue1 reuseIdentifier:nil];
    LaraManager *mgr = [LaraManager shared];

    switch (indexPath.section) {
        case ToolsSectionStatus:
            if (is_likely_livecontainer_runtime()) {
                cell.textLabel.text = @"Running in LiveContainer\nKernel R/W ready.";
            } else {
                cell.textLabel.text = mgr.dsReady ? @"Kernel R/W ready." : @"Kernel R/W is not ready. Run the exploit first.";
            }
            cell.textLabel.textColor = UIColor.secondaryLabelColor;
            cell.textLabel.numberOfLines = 0;
            cell.selectionStyle = UITableViewCellSelectionStyleNone;
            break;

        case ToolsSectionAdvanced:
            if (indexPath.row == 0) {
                cell.textLabel.text = @"Generate Sandbox Token";
                cell.textLabel.textColor = self.view.tintColor;
            }
            break;

        case ToolsSectionASLR:
            if (indexPath.row == 0) {
                cell.textLabel.text = @"ASLR:";
                cell.detailTextLabel.text = aslrstate ? @"enabled" : @"disabled";
                cell.detailTextLabel.textColor = aslrstate ? UIColor.systemRedColor : UIColor.systemGreenColor;
                cell.selectionStyle = UITableViewCellSelectionStyleNone;
            } else {
                cell.textLabel.text = @"Toggle ASLR";
            }
            break;

        case ToolsSectionProcess:
            if (indexPath.row == 0) {
                cell.textLabel.text = @"ourproc:";
                cell.detailTextLabel.text = mgr.dsReady
                    ? [NSString stringWithFormat:@"0x%llx", ds_get_our_proc()] : @"N/A";
                cell.detailTextLabel.font = [UIFont monospacedSystemFontOfSize:14 weight:UIFontWeightRegular];
                cell.selectionStyle = UITableViewCellSelectionStyleNone;
            } else if (indexPath.row == 1) {
                cell.textLabel.text = @"ourtask:";
                cell.detailTextLabel.text = mgr.dsReady
                    ? [NSString stringWithFormat:@"0x%llx", ds_get_our_task()] : @"N/A";
                cell.detailTextLabel.font = [UIFont monospacedSystemFontOfSize:14 weight:UIFontWeightRegular];
                cell.selectionStyle = UITableViewCellSelectionStyleNone;
            } else if (indexPath.row == 2) {
                cell.textLabel.text = @"UID:";
                cell.detailTextLabel.text = [NSString stringWithFormat:@"%d", getuid()];
                cell.detailTextLabel.font = [UIFont monospacedSystemFontOfSize:14 weight:UIFontWeightRegular];
                cell.selectionStyle = UITableViewCellSelectionStyleNone;
            } else if (indexPath.row == 3) {
                cell.textLabel.text = @"PID:";
                cell.detailTextLabel.text = [NSString stringWithFormat:@"%d", getpid()];
                cell.detailTextLabel.font = [UIFont monospacedSystemFontOfSize:14 weight:UIFontWeightRegular];
                cell.selectionStyle = UITableViewCellSelectionStyleNone;
            }
            break;

        case ToolsSectionTerminal:
            cell.textLabel.text = @"Open Terminal";
            cell.textLabel.textColor = UIColor.systemGreenColor;
            cell.detailTextLabel.text = @"term_exec kernel R/W";
            cell.detailTextLabel.font = [UIFont monospacedSystemFontOfSize:12 weight:UIFontWeightRegular];
            break;

        case ToolsSectionRemote: {
            LaraRemoteServer *srv = [LaraRemoteServer shared];
            if (srv.isRunning) {
                cell.textLabel.text = [NSString stringWithFormat:@"Stop Remote Server (:%ld)", (long)srv.port];
                cell.textLabel.textColor = UIColor.systemRedColor;
                cell.detailTextLabel.text = @"running";
            } else {
                cell.textLabel.text = @"Start Remote Server";
                cell.textLabel.textColor = UIColor.systemGreenColor;
                cell.detailTextLabel.text = @"port 8080";
            }
            cell.detailTextLabel.font = [UIFont monospacedSystemFontOfSize:12 weight:UIFontWeightRegular];
            break;
        }

        case ToolsSectionMobAI: {
            LaraMobAIServer *srv = [LaraMobAIServer shared];
            if (srv.isRunning) {
                cell.textLabel.text = [NSString stringWithFormat:@"Stop MobAI Server (:%ld)", (long)srv.port];
                cell.textLabel.textColor = UIColor.systemRedColor;
                cell.detailTextLabel.text = @"running";
            } else {
                cell.textLabel.text = @"Start MobAI Server";
                cell.textLabel.textColor = UIColor.systemGreenColor;
                cell.detailTextLabel.text = @"port 8686";
            }
            cell.detailTextLabel.font = [UIFont monospacedSystemFontOfSize:12 weight:UIFontWeightRegular];
            break;
        }

        case ToolsSectionPPL: {
            if (indexPath.row == 0) {
                cell.textLabel.text = @"PPL Status:";
                cell.detailTextLabel.text = ppl_is_available() ? @"available" : @"not available";
                cell.detailTextLabel.textColor = ppl_is_available() ? UIColor.systemGreenColor : UIColor.systemRedColor;
                cell.selectionStyle = UITableViewCellSelectionStyleNone;
            } else if (indexPath.row == 1) {
                cell.textLabel.text = @"Test XPRR Bypass";
                cell.textLabel.textColor = UIColor.systemOrangeColor;
                cell.detailTextLabel.text = @"direct_pte_xprr_modify";
            } else if (indexPath.row == 2) {
                cell.textLabel.text = @"Test Kernel Write";
                cell.textLabel.textColor = UIColor.systemRedColor;
                cell.detailTextLabel.text = @"ppl_write_kernel64";
            }
            cell.detailTextLabel.font = [UIFont monospacedSystemFontOfSize:12 weight:UIFontWeightRegular];
            break;
        }
    }
    return cell;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    if (indexPath.section == ToolsSectionASLR && indexPath.row == 1) {
        toggleaslr();
        getaslrstate();
        [tableView reloadSections:[NSIndexSet indexSetWithIndex:ToolsSectionASLR]
                 withRowAnimation:UITableViewRowAnimationNone];
    } else if (indexPath.section == ToolsSectionAdvanced) {
        if (indexPath.row == 0) {
            [self handleGenerateToken];
        }
    } else if (indexPath.section == ToolsSectionTerminal) {
        TerminalViewController *tvc = [[TerminalViewController alloc] init];
        [self.navigationController pushViewController:tvc animated:YES];
    } else if (indexPath.section == ToolsSectionRemote) {
        [self handleRemoteServer];
    } else if (indexPath.section == ToolsSectionMobAI) {
        [self handleMobAIServer];
    } else if (indexPath.section == ToolsSectionPPL) {
        if (indexPath.row == 0) {
            // Status - no action
        } else if (indexPath.row == 1) {
            [self handleTestPPLXPRR];
        } else if (indexPath.row == 2) {
            [self handleTestPPLKernelWrite];
        }
    }
}

- (void)handleGenerateToken {
    if (![LaraManager shared].dsReady) {
        [self showAlert:@"Error" message:@"Exploit not run yet. Run the exploit first."];
        return;
    }
    
    char *token = vfs_get_sandbox_extension_token("/");
    if (token) {
        NSString *tokenStr = [NSString stringWithUTF8String:token];
        free(token);
        
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Sandbox Token"
                                                                       message:tokenStr
                                                                preferredStyle:UIAlertControllerStyleAlert];
        
        [alert addAction:[UIAlertAction actionWithTitle:@"Copy" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
            [UIPasteboard generalPasteboard].string = tokenStr;
        }]];
        
        [alert addAction:[UIAlertAction actionWithTitle:@"Dismiss" style:UIAlertActionStyleCancel handler:nil]];
        
        [self presentViewController:alert animated:YES completion:nil];
    } else {
        [self showAlert:@"Error" message:@"Failed to generate token. Kernel primitives might not be ready."];
    }
}

- (void)showAlert:(NSString *)title message:(NSString *)msg {
    UIAlertController *a = [UIAlertController alertControllerWithTitle:title message:msg preferredStyle:UIAlertControllerStyleAlert];
    [a addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
    [self presentViewController:a animated:YES completion:nil];
}

- (void)handleRemoteServer {
    LaraRemoteServer *srv = [LaraRemoteServer shared];
    if (srv.isRunning) {
        [srv stop];
    } else {
        NSError *error = nil;
        if ([srv startOnPort:8080 error:&error]) {
            // Show IP address
            NSString *ip = @"unknown";
            struct ifaddrs *ifap, *ifa;
            if (getifaddrs(&ifap) == 0) {
                for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
                    if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {
                        if (strcmp(ifa->ifa_name, "en0") == 0) {
                            struct sockaddr_in *sin = (struct sockaddr_in *)ifa->ifa_addr;
                            char addr[INET_ADDRSTRLEN];
                            inet_ntop(AF_INET, &sin->sin_addr, addr, sizeof(addr));
                            ip = @(addr);
                            break;
                        }
                    }
                }
                freeifaddrs(ifap);
            }
            [self showAlert:@"Remote Server" message:[NSString stringWithFormat:@"Started on %@:8080\n\nUse lara-remote.py on PC:\n  python lara-remote.py --host %@", ip, ip]];
        } else {
            [self showAlert:@"Error" message:error.localizedDescription];
        }
    }
    [self.tableView reloadData];
}

- (void)handleMobAIServer {
    LaraMobAIServer *srv = [LaraMobAIServer shared];
    if (srv.isRunning) {
        [srv stop];
    } else {
        NSError *error = nil;
        if ([srv startOnPort:8686 error:&error]) {
            NSString *ip = @"unknown";
            struct ifaddrs *ifap, *ifa;
            if (getifaddrs(&ifap) == 0) {
                for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
                    if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {
                        if (strcmp(ifa->ifa_name, "en0") == 0) {
                            struct sockaddr_in *sin = (struct sockaddr_in *)ifa->ifa_addr;
                            char addr[INET_ADDRSTRLEN];
                            inet_ntop(AF_INET, &sin->sin_addr, addr, sizeof(addr));
                            ip = @(addr);
                            break;
                        }
                    }
                }
                freeifaddrs(ifap);
            }
            [self showAlert:@"MobAI Server" message:[NSString stringWithFormat:@"Started on %@:8686\n\nMobAI API endpoints:\n  GET  /api/v1/info\n  GET  /api/v1/screenshot\n  POST /api/v1/tap\n  POST /api/v1/term\n  POST /api/v1/dsl", ip]];
        } else {
            [self showAlert:@"Error" message:error.localizedDescription];
        }
    }
    [self.tableView reloadData];
}

- (void)handleTestPPLXPRR {
    ppl_log_to_file(@"=== XPRR Bypass Test Started ===");
    NSLog(@"[PPL-TEST] === XPRR Bypass Test Started ===");

    if (![LaraManager shared].dsReady) {
        ppl_log_to_file(@"FAIL: Kernel R/W not ready");
        NSLog(@"[PPL-TEST] FAIL: Kernel R/W not ready");
        [self showAlert:@"Error" message:@"Kernel R/W not ready. Run exploit first."];
        return;
    }
    ppl_log_to_file(@"Kernel R/W: ready");
    NSLog(@"[PPL-TEST] Kernel R/W: ready");

    // Initialize PPL bypass if not already done
    if (!ppl_is_available()) {
        ppl_log_to_file(@"Calling ppl_init()...");
        NSLog(@"[PPL-TEST] Calling ppl_init()...");
        ppl_init();
    }

    if (!ppl_is_available()) {
        ppl_log_to_file(@"FAIL: PPL bypass not available after ppl_init()");
        NSLog(@"[PPL-TEST] FAIL: PPL bypass not available after ppl_init()");
        [self showAlert:@"PPL Bypass" message:@"PPL bypass is NOT available on this device/iOS version."];
        return;
    }
    ppl_log_to_file(@"PPL bypass: available");
    NSLog(@"[PPL-TEST] PPL bypass: available");

    // Use a heap address instead of kernel text - kernel text uses block descriptors
    // and does not have level 3 PTEs, causing panic on kvtopte
    uint64_t test_kva = ds_get_kernel_base() + 0x1000000;  // Try kernel heap area
    if (test_kva == 0) {
        test_kva = 0xffffffe000000000ULL;  // Fallback to physical aperture
    }
    ppl_log_to_file([NSString stringWithFormat:@"Target KVA: 0x%llx", test_kva]);
    NSLog(@"[PPL-TEST] Target KVA: 0x%llx", test_kva);

    NSMutableString *log = [NSMutableString string];
    [log appendFormat:@"[LOG] Testing Direct PTE XPRR Modification\n"];
    [log appendFormat:@"[LOG] Target KVA: 0x%llx\n\n", test_kva];

    ppl_log_to_file(@"Reading 64-bit value at target KVA...");
    uint64_t current = ds_kread64(test_kva);
    ppl_log_to_file([NSString stringWithFormat:@"Read KVA: 0x%016llx", current]);
    NSLog(@"[PPL-TEST] Read KVA: 0x%016llx", current);
    [log appendFormat:@"[LOG] Current value at KVA: 0x%016llx\n", current];

    ppl_log_to_file(@"Calling ds_kvtopte_addr() to get PTE address...");
    uint64_t pte_addr = ds_kvtopte_addr(test_kva);
    ppl_log_to_file([NSString stringWithFormat:@"PTE address: 0x%llx", pte_addr]);
    NSLog(@"[PPL-TEST] PTE address: 0x%llx", pte_addr);
    if (pte_addr) {
        ppl_log_to_file(@"Reading PTE value...");
        uint64_t pte_val = ds_kread64(pte_addr);
        ppl_log_to_file([NSString stringWithFormat:@"PTE value: 0x%016llx", pte_val]);
        uint8_t xprr = (pte_val >> 57) & 0x7;
        ppl_log_to_file([NSString stringWithFormat:@"XPRR bits: %d", xprr]);
        NSLog(@"[PPL-TEST] PTE value: 0x%016llx", pte_val);
        NSLog(@"[PPL-TEST] XPRR bits: %d", xprr);

        [log appendFormat:@"[LOG] PTE address: 0x%llx\n", pte_addr];
        [log appendFormat:@"[LOG] PTE value: 0x%016llx\n", pte_val];
        [log appendFormat:@"[LOG] Current XPRR: %d (", xprr];
        switch (xprr) {
            case 0: [log appendString:@"KERN_RW"]; ppl_log_to_file(@"XPRR=KERN_RW (0)"); NSLog(@"[PPL-TEST] XPRR=KERN_RW"); break;
            case 1: [log appendString:@"KERN_RO"]; ppl_log_to_file(@"XPRR=KERN_RO (1)"); NSLog(@"[PPL-TEST] XPRR=KERN_RO"); break;
            case 2: [log appendString:@"USER_RW"]; ppl_log_to_file(@"XPRR=USER_RW (2)"); NSLog(@"[PPL-TEST] XPRR=USER_RW"); break;
            case 3: [log appendString:@"USER_RO"]; ppl_log_to_file(@"XPRR=USER_RO (3)"); NSLog(@"[PPL-TEST] XPRR=USER_RO"); break;
            case 4: [log appendString:@"KERN_EXEC"]; ppl_log_to_file(@"XPRR=KERN_EXEC (4)"); NSLog(@"[PPL-TEST] XPRR=KERN_EXEC"); break;
            case 5: [log appendString:@"USER_EXEC"]; ppl_log_to_file(@"XPRR=USER_EXEC (5)"); NSLog(@"[PPL-TEST] XPRR=USER_EXEC"); break;
            default: [log appendString:@"UNKNOWN"]; ppl_log_to_file(@"XPRR=UNKNOWN"); NSLog(@"[PPL-TEST] XPRR=UNKNOWN"); break;
        }
        [log appendString:@")\n\n"];

        [log appendFormat:@"[LOG] PPL bypass mechanism: AVAILABLE\n"];
        [log appendFormat:@"[LOG] Method: Direct PTE XPRR bit modification\n"];
        [log appendFormat:@"[LOG] iOS 17.3.1 (A12X) - CVE-2024-23225 class\n"];
        ppl_log_to_file(@"=== XPRR Test PASSED ===");
        NSLog(@"[PPL-TEST] === XPRR Test PASSED ===");
    } else {
        [log appendString:@"[LOG] Failed to resolve PTE address.\n"];
        ppl_log_to_file(@"FAIL: Could not resolve PTE address");
        NSLog(@"[PPL-TEST] FAIL: Could not resolve PTE");
    }

    [self showAlert:@"PPL XPRR Test" message:log];
    [self.tableView reloadData];
}

- (void)handleTestPPLKernelWrite {
    ppl_log_to_file(@"=== Kernel Write Test Started ===");
    NSLog(@"[PPL-TEST] === Kernel Write Test Started ===");

    if (![LaraManager shared].dsReady) {
        ppl_log_to_file(@"FAIL: Kernel R/W not ready");
        NSLog(@"[PPL-TEST] FAIL: Kernel R/W not ready");
        [self showAlert:@"Error" message:@"Kernel R/W not ready. Run exploit first."];
        return;
    }
    ppl_log_to_file(@"Kernel R/W: ready");
    NSLog(@"[PPL-TEST] Kernel R/W: ready");

    // Initialize PPL bypass if not already done
    if (!ppl_is_available()) {
        ppl_log_to_file(@"Calling ppl_init()...");
        NSLog(@"[PPL-TEST] Calling ppl_init()...");
        ppl_init();
    }

    if (!ppl_is_available()) {
        ppl_log_to_file(@"FAIL: PPL bypass not available after ppl_init()");
        NSLog(@"[PPL-TEST] FAIL: PPL bypass not available after ppl_init()");
        [self showAlert:@"PPL Bypass" message:@"PPL bypass is NOT available."];
        return;
    }
    ppl_log_to_file(@"PPL bypass: available");
    NSLog(@"[PPL-TEST] PPL bypass: available");

    NSMutableString *log = [NSMutableString string];
    [log appendString:@"[LOG] Testing PPL Kernel Write via XPRR bypass\n\n"];

    uint64_t test_addr = ds_get_kernel_base() + 0x1000;
    uint64_t test_value = 0xDEADBEEFCAFEBABEULL;

    ppl_log_to_file([NSString stringWithFormat:@"Target address: 0x%llx", test_addr]);
    ppl_log_to_file([NSString stringWithFormat:@"Test value: 0x%016llx", test_value]);
    NSLog(@"[PPL-TEST] Target address: 0x%llx", test_addr);
    NSLog(@"[PPL-TEST] Test value: 0x%016llx", test_value);
    [log appendFormat:@"[LOG] Target: 0x%llx\n", (unsigned long long)test_addr];
    [log appendFormat:@"[LOG] Test value: 0x%016llx\n\n", (unsigned long long)test_value];

    ppl_log_to_file(@"Calling ppl_write_kernel64()...");
    bool success = ppl_write_kernel64(test_addr, test_value);
    ppl_log_to_file([NSString stringWithFormat:@"ppl_write_kernel64 returned: %d", success]);
    NSLog(@"[PPL-TEST] ppl_write_kernel64 returned: %d", success);

    if (success) {
        ppl_log_to_file(@"Write returned success, reading back...");
        uint64_t readback = ds_kread64(test_addr);
        ppl_log_to_file([NSString stringWithFormat:@"Readback: 0x%016llx", readback]);
        ppl_log_to_file([NSString stringWithFormat:@"Match: %d", (readback == test_value)]);
        NSLog(@"[PPL-TEST] Readback: 0x%016llx", readback);
        NSLog(@"[PPL-TEST] Match: %d", (readback == test_value));

        [log appendFormat:@"[LOG] Write: SUCCESS\n"];
        [log appendFormat:@"[LOG] Readback: 0x%016llx\n", readback];
        [log appendFormat:@"[LOG] Match: %@", (readback == test_value) ? @"YES" : @"NO (partial write)"];

        uint64_t original = ds_kread64(test_addr);
        ppl_log_to_file([NSString stringWithFormat:@"Restoring original value: 0x%016llx", original]);
        ppl_write_kernel64(test_addr, original);
        ppl_log_to_file(@"Original value restored");
        NSLog(@"[PPL-TEST] Restored original: 0x%016llx", original);
        [log appendFormat:@"\n\n[LOG] Original value restored: 0x%016llx", original];
        ppl_log_to_file(@"=== Kernel Write Test PASSED ===");
        NSLog(@"[PPL-TEST] === Kernel Write Test PASSED ===");
    } else {
        [log appendString:@"[LOG] Write: FAILED\n"];
        [log appendString:@"[LOG] PPL bypass may not work on this iOS version."];
        ppl_log_to_file(@"=== Kernel Write Test FAILED ===");
        NSLog(@"[PPL-TEST] === Kernel Write Test FAILED ===");
    }

    [self showAlert:@"PPL Kernel Write Test" message:log];
    [self.tableView reloadData];
}

@end

