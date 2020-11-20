//
//  BlizzardLog.m
//  Blizzard Jailbreak
//
//  Created by GeoSn0w on 8/10/20.
//  Copyright © 2020 GeoSn0w. All rights reserved.
//

#import "BlizzardLog.h"
#import "../Kernel Utilities/system_reboot.h"
#import "../Exploits/sock_port/exploit.h"
#import "../Blizzard Jailbreak/blizzardJailbreak.h"
#import "../APFS Utilities/rootfs_remount.h"
#import "../Exploits/FreeTheSandbox/freethesandbox.h"
#define currentVer(v)  ([[[UIDevice currentDevice] systemVersion] compare:@v options:NSNumericSearch] != NSOrderedDescending)
@interface BlizzardLog()
@end

static BlizzardLog *BlizzLogger;

@implementation BlizzardLog

+ (instancetype)BlizzLogger {
    return BlizzLogger;
}

int dismissButtonActionType = 0;
int IS_BLIZZARD_DEBUG = 0;
int shouldUnjailbreak = 0;

- (void)viewDidLoad {
    [super viewDidLoad];
    if (IS_BLIZZARD_DEBUG != 1){
        [self redirectSTD:STDOUT_FILENO];
    }
    NSRange lastLine = NSMakeRange(self.uiLogView.text.length - 1, 1);
    [self.uiLogView scrollRangeToVisible:lastLine];
    
    dispatch_async(dispatch_get_global_queue(0, 0), ^{
        [self runJailbreak];
        dispatch_async(dispatch_get_main_queue(), ^{
            //update UI in main thread.
        });
    });
    
}
-(void) runJailbreak {
    if (currentVer("11.4")){
        if (ios11_exploit_init() == 0){
            if (shouldUnjailbreak == 1){
                if (unjailbreakBlizzard() == 0){
                    dismissButtonActionType = 1;
                    printf("Unjailbroken!\n");
                    [self.dismissLog setTitle:@"REBOOT DEVICE" forState:UIControlStateNormal];
                }
                return;
            }
            if (remountFileSystem() == 0 && shouldReboot == 1 && shouldUnjailbreak != 1){
                dismissButtonActionType = 1;
                [self.dismissLog setTitle:@"REBOOT DEVICE" forState:UIControlStateNormal];
            } else {
                printf("Used the old remount, tee hee\n");
                installBootStrap();
                cleanupAfterBlizzard();
            }
        }
    } else if (currentVer("13.7")){
        extern char *get_current_deviceModel(void);
        printf("Model: %s\n", get_current_deviceModel());
        printf("Version: %s\n", [[[UIDevice currentDevice] systemVersion] UTF8String]);
        
        extern uint64_t kaslr;
        extern mach_port_t tfp0_port;
    
        // Activate tfp0-persis program
        mach_port_t midi_bsport = 0;
        extern kern_return_t bootstrap_look_up(mach_port_t bp, const char *service_name, mach_port_t *sp);
        bootstrap_look_up(bootstrap_port, "com.apple.midiserver", &midi_bsport);
        if(!midi_bsport){
            //printf("run_exploit_or_achieve_tf0 failed: bootstrap_look_up has problem\n");
            exit(1);
        }
        
        mach_port_t stored_ports[3] = {0};
        stored_ports[0] = mach_task_self();
        stored_ports[2] = midi_bsport;
        mach_ports_register(mach_task_self(), stored_ports, 3);
        // Waiting for installation
        sleep(2);
        
        tfp0_port = 0;
        task_get_special_port(mach_task_self(), TASK_ACCESS_PORT, &tfp0_port);
        if(tfp0_port == 0){
            printf("require to run exploit first\n");
            
            extern bool check_device_compatibility(void);
            if(check_device_compatibility() == false){
                printf("Execution pause: Not found offsets set for current device(model: %s)\n", get_current_deviceModel());
                return;
            }
            
            extern void exploit_start(void);
            iOS13_exploit_init();
            
            printf("persis tfp0 installed, you can quit app now...\n");
            return;
        }
        stored_ports[2] = 0;
        mach_ports_register(mach_task_self(), stored_ports, 3);
        
        printf("tfp0: 0x%x\n", tfp0_port);
        pid_for_task(tfp0_port, (int*)&kaslr);
        printf("kaslr: 0x%x\n", (uint32_t)kaslr);
        
    }
}
- (IBAction)dismissLogWindow:(id)sender {
    if (dismissButtonActionType == 0){
        [self dismissViewControllerAnimated:YES completion:nil];
    } else if (dismissButtonActionType == 1){
        [self loadSystemNotif];
    }
}

-(void)textViewDidChange:(UITextView *)textView
{
    NSRange lastLine = NSMakeRange(self.uiLogView.text.length - 1, 1);
    [self.uiLogView scrollRangeToVisible:lastLine];
}

- (void)redirectNotificationHandle:(NSNotification *)nf{
    NSData *data = [[nf userInfo] objectForKey:NSFileHandleNotificationDataItem];
    NSString *str = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    
    self.uiLogView.text = [NSString stringWithFormat:@"%@\n%@",self.uiLogView.text, str];
    NSRange lastLine = NSMakeRange(self.uiLogView.text.length - 1, 1);
    [self.uiLogView scrollRangeToVisible:lastLine];
    [[nf object] readInBackgroundAndNotify];
}

- (void)redirectSTD:(int )fd{
    setvbuf(stdout, nil, _IONBF, 0);
    NSPipe * pipe = [NSPipe pipe] ;
    NSFileHandle *pipeReadHandle = [pipe fileHandleForReading] ;
    dup2([[pipe fileHandleForWriting] fileDescriptor], fd) ;
    
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(redirectNotificationHandle:)
                                                 name:NSFileHandleReadCompletionNotification
                                               object:pipeReadHandle] ;
    [pipeReadHandle readInBackgroundAndNotify];
}

- (void)loadSystemNotif {
    dispatch_async(dispatch_get_main_queue(), ^{
        UIAlertController *apfsNoticeController = [UIAlertController alertControllerWithTitle:(@"Blizzard Jailbreak") message:(@"The APFS Snapshot has been successfully renamed! Your device will reboot now. If you wanna jailbreak, please come back to the app and re-jailbreak upon reboot.") preferredStyle:UIAlertControllerStyleAlert];
        [apfsNoticeController addAction:[UIAlertAction actionWithTitle:(@"Dismiss") style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
            reboot(RB_NOSYNC);
        }]];
        [self presentViewController:apfsNoticeController animated:YES completion:nil];
    });
}

@end
