
#include "arm_thumb_bl.h"
#include "gtest/gtest.h"

TEST(arm_thumb_bl, positive) {
    uint32_t const pc = 0x8001ec2;
    uint16_t const instr1 = 0xf000;
    uint16_t const instr2 = 0xf861;
    uint32_t const targetAddress = 0x8001f88;

    EXPECT_TRUE(arm_thumb_bl::isValid(instr1));
    EXPECT_FALSE(arm_thumb_bl::isValid(instr2));
    EXPECT_TRUE(arm_thumb_bl::isValid(instr1, instr2));
    EXPECT_EQ(arm_thumb_bl(instr1, instr2, pc).getTargetAddress(), targetAddress);
}

TEST(arm_thumb_bl, negative) {
    uint32_t const pc = 0x8001ebe;
    uint16_t const instr1 = 0xf7fe;
    uint16_t const instr2 = 0xfd77;
    uint32_t const targetAddress = 0x80009b0;

    EXPECT_TRUE(arm_thumb_bl::isValid(instr1));
    EXPECT_FALSE(arm_thumb_bl::isValid(instr2));
    EXPECT_TRUE(arm_thumb_bl::isValid(instr1, instr2));
    EXPECT_EQ(arm_thumb_bl(instr1, instr2, pc).getTargetAddress(), targetAddress);
}

