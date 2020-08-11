//
//  BlizzardLog.m
//  Blizzard Jailbreak
//
//  Created by GeoSn0w on 8/10/20.
//  Copyright © 2020 GeoSn0w. All rights reserved.
//

#import "BlizzardLog.h"

@interface BlizzardLog()

@end

@implementation BlizzardLog


- (void)viewDidLoad {
    [super viewDidLoad];
    [self redirectSTD:STDOUT_FILENO];
    NSRange lastLine = NSMakeRange(self.uiLogView.text.length - 1, 1);
    [self.uiLogView scrollRangeToVisible:lastLine];
}

- (IBAction)dismissLogWindow:(id)sender {
    [self dismissViewControllerAnimated:YES completion:nil];
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

/*
#pragma mark - Navigation

// In a storyboard-based application, you will often want to do a little preparation before navigation
- (void)prepareForSegue:(UIStoryboardSegue *)segue sender:(id)sender {
    // Get the new view controller using [segue destinationViewController].
    // Pass the selected object to the new view controller.
}
*/

@end
