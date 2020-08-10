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
 
}
- (IBAction)blizzardInit:(id)sender {
    exploit_init();
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
