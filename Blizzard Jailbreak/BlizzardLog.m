//
//  BlizzardLog.m
//  Blizzard Jailbreak
//
//  Created by GeoSn0w on 8/10/20.
//  Copyright © 2020 GeoSn0w. All rights reserved.
//

#import "BlizzardLog.h"
#import "../Kernel Utilities/system_reboot.h"
#import "../sock_port/exploit.h"
#import "../Blizzard Jailbreak/blizzardJailbreak.h"
#import "../APFS Utilities/rootfs_remount.h"

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
    if (exploit_init() == 0){
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
            cleanupAfterBlizzard();
        }
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
