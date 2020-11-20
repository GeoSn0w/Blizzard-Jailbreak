//
//  BlizzardLog.h
//  Blizzard Jailbreak
//
//  Created by GeoSn0w on 8/10/20.
//  Copyright © 2020 GeoSn0w. All rights reserved.
//

#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

@interface BlizzardLog : UIViewController
@property (weak, nonatomic) IBOutlet UIButton *dismissLog;
@property (weak, nonatomic) IBOutlet UITextView *uiLogView;
+ (instancetype)BlizzLogger;
- (void)displaySnapshotNotice;
- (void)customizeBtnAtUI;
@end

NS_ASSUME_NONNULL_END
