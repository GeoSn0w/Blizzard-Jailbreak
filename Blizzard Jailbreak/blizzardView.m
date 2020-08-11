//
//  blizzardView.m
//  Blizzard Jailbreak
//
//  Created by GeoSn0w on 8/10/20.
//  Copyright © 2020 GeoSn0w. All rights reserved.
//

#import "blizzardView.h"
#include "blizzardJailbreak.h"


@interface blizzardView ()

@end

@implementation blizzardView

- (void)viewDidLoad {
    [super viewDidLoad];
    printf("Blizzard Jailbreak\nby GeoSn0w (@FCE365)\n\nAn Open-Source Jailbreak for you to study and dissect :-)\n");
}
- (IBAction)blizzardInit:(id)sender {
    [self performSegueWithIdentifier:@"vc" sender:self];
    _blizzardInit.enabled = NO;
    [_blizzardInit setTitle:@"JAILBREAKING..." forState:UIControlStateDisabled];
    exploit_init();
    [_blizzardInit setTitle:@"JAILBROKEN" forState:UIControlStateDisabled];
}

@end
