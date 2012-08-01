/*
 * AMLOGIC T13 LCD panel driver.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the named License,
 * or any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA
 *
 * Author:  Tim Yao <timyao@amlogic.com>
 *
 */

#include <linux/init.h>
#include <linux/version.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/vout/tcon.h>

#include <mach/gpio.h>
#include <mach/am_regs.h>
#include <mach/pinmux.h>
#include <mach/power_gate.h>
#include <linux/delay.h>

#include <linux/twx_tc101.h>

#ifdef CONFIG_SN7325
    #include <linux/sn7325.h>
#endif

/*
For 8726M, Hanstar 7" */ 
#define LCD_WIDTH       1280
#define LCD_HEIGHT      768
#define MAX_WIDTH       1440
#define MAX_HEIGHT      798
#define VIDEO_ON_LINE   22

//extern void msleep(unsigned int msecs);

static void t13_power_on(void);
static void t13_power_off(void);
void power_on_backlight(void);
void power_off_backlight(void);

static tcon_conf_t tcon_config =
{
    .width      = LCD_WIDTH,
    .height     = LCD_HEIGHT,
    .max_width  = MAX_WIDTH,
    .max_height = MAX_HEIGHT,
    .video_on_line = VIDEO_ON_LINE,
    .pll_ctrl = 0x0667,      //30MHz
    .clk_ctrl = 0x1fc1,
    .gamma_cntl_port = (1 << LCD_GAMMA_EN) | (0 << LCD_GAMMA_RVS_OUT) | (1 << LCD_GAMMA_VCOM_POL),
    .gamma_vcom_hswitch_addr = 0,
    .rgb_base_addr = 0xf0,
    .rgb_coeff_addr = 0x74a,
    .pol_cntl_addr = (0x0 << LCD_CPH1_POL) |(0x1 << LCD_HS_POL) | (0x1 << LCD_VS_POL),
    .dith_cntl_addr = 0x600,
    .sth1_hs_addr = 27,
    .sth1_he_addr = 17,
    .sth1_vs_addr = 0,
    .sth1_ve_addr = MAX_HEIGHT - 1,
    .sth2_hs_addr = 0,
    .sth2_he_addr = 0,
    .sth2_vs_addr = 0,
    .sth2_ve_addr = 0,
    .oeh_hs_addr = 67,
    .oeh_he_addr = 67+LCD_WIDTH-1,
    .oeh_vs_addr = VIDEO_ON_LINE,
    .oeh_ve_addr = VIDEO_ON_LINE+LCD_HEIGHT-1,
    .vcom_hswitch_addr = 0,
    .vcom_vs_addr = 0,
    .vcom_ve_addr = 0,
    .cpv1_hs_addr = 0,
    .cpv1_he_addr = 0,
    .cpv1_vs_addr = 0,
    .cpv1_ve_addr = 0,
    .cpv2_hs_addr = 0,
    .cpv2_he_addr = 0,
    .cpv2_vs_addr = 0,
    .cpv2_ve_addr = 0,
    .stv1_hs_addr = 0,
    .stv1_he_addr = MAX_WIDTH - 1,
    .stv1_vs_addr = 5,
    .stv1_ve_addr = 3,
    .stv2_hs_addr = 0,
    .stv2_he_addr = 0,
    .stv2_vs_addr = 0,
    .stv2_ve_addr = 0,
    .oev1_hs_addr = 0,
    .oev1_he_addr = 0,
    .oev1_vs_addr = 0,
    .oev1_ve_addr = 0,
    .oev2_hs_addr = 0,
    .oev2_he_addr = 0,
    .oev2_vs_addr = 0,
    .oev2_ve_addr = 0,
    .oev3_hs_addr = 0,
    .oev3_he_addr = 0,
    .oev3_vs_addr = 0,
    .oev3_ve_addr = 0,
    .inv_cnt_addr = (0<<LCD_INV_EN) | (0<<LCD_INV_CNT),
    .tcon_misc_sel_addr = (1<<LCD_STV1_SEL) | (1<<LCD_STV2_SEL),
    .dual_port_cntl_addr = (1<<LCD_TTL_SEL) | (1<<LCD_ANALOG_SEL_CPH3) | (1<<LCD_ANALOG_3PHI_CLK_SEL) | (0<<RGB_SWP) | (0<<BIT_SWP),
    .flags = 0,
    .screen_width = 5,
    .screen_height = 3,
    .sync_duration_num = 60,
    .sync_duration_den = 1,
    .power_on=t13_power_on,
    .power_off=t13_power_off,
    .backlight_on = power_on_backlight,
    .backlight_off = power_off_backlight,
};
static struct resource tcon_resources[] = {
    [0] = {
        .start = (ulong)&tcon_config,
        .end   = (ulong)&tcon_config + sizeof(tcon_conf_t) - 1,
        .flags = IORESOURCE_MEM,
    },
};

static void t13_setup_gama_table(tcon_conf_t *pConf)
{
    int i;
    const unsigned short gamma_adjust[256] = {
        0,2,3,5,7,8,10,11,13,15,16,18,20,21,23,26,28,29,31,32,34,35,36,37,38,39,40,41,42,43,44,45,
				46,47,48,49,49,50,51,52,53,54,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,74,
				75,76,77,78,79,80,80,81,81,82,83,84,85,86,86,87,88,89,89,90,91,92,93,94,95,96,97,98,99,100,100,101,
				102,103,104,105,106,107,109,109,110,112,113,114,115,117,118,120,122,124,126,129,131,133,134,135,137,138,139,140,141,142,143,144,
				145,145,146,147,148,149,149,150,151,152,152,153,154,155,156,156,157,158,159,159,160,161,162,163,164,164,165,166,167,168,169,170,
				171,172,173,173,174,176,176,178,178,179,181,182,183,184,185,186,187,188,189,190,191,192,194,194,195,196,198,198,199,200,201,202,
				203,204,205,206,207,208,209,209,210,211,211,212,213,214,215,215,216,217,217,218,219,220,220,221,221,222,223,223,224,224,225,226,
				226,227,227,228,229,229,230,230,231,232,232,233,234,234,235,236,237,238,239,239,241,242,242,244,245,246,248,249,251,252,253,255,
    };

    for (i=0; i<256; i++) {
        pConf->GammaTableR[i] = gamma_adjust[i] << 2;
        pConf->GammaTableG[i] = gamma_adjust[i] << 2;
        pConf->GammaTableB[i] = gamma_adjust[i] << 2;
    }
}

void power_on_backlight(void)
{            
    set_gpio_val(GPIOA_bank_bit(7), GPIOA_bit_bit0_14(7), 1);
    set_gpio_mode(GPIOA_bank_bit(7), GPIOA_bit_bit0_14(7), GPIO_OUTPUT_MODE); 
}

void power_off_backlight(void)
{        
    set_gpio_val(GPIOA_bank_bit(7), GPIOA_bit_bit0_14(7), 0);
    set_gpio_mode(GPIOA_bank_bit(7), GPIOA_bit_bit0_14(7), GPIO_OUTPUT_MODE);         
}

static void power_on_lcd(void)
{   
    //LCD3.3V  EIO -> OD0: 0 
#ifdef CONFIG_SN7325
    configIO(0, 0);
    setIO_level(0, 0, 0);
#else
set_gpio_val(GPIOD_bank_bit2_24(20), GPIOD_bit_bit2_24(20), 0);
set_gpio_mode(GPIOD_bank_bit2_24(20), GPIOD_bit_bit2_24(20), GPIO_OUTPUT_MODE);		  
#endif    
    msleep(20);
    //AVDD  EIO -> OD4: 1
#ifdef CONFIG_SN7325
    configIO(0, 0);
    setIO_level(0, 1, 4);
#else
set_gpio_val(GPIOA_bank_bit(3), GPIOA_bit_bit0_14(3), 1);
set_gpio_mode(GPIOA_bank_bit(3), GPIOA_bit_bit0_14(3), GPIO_OUTPUT_MODE);		
#endif
    msleep(50);    
}

static void power_off_lcd(void)
{    
    msleep(50);
    //AVDD  EIO -> OD4: 0
#ifdef CONFIG_SN7325
    configIO(0, 0);
    setIO_level(0, 0, 4);
#else
set_gpio_val(GPIOA_bank_bit(3), GPIOA_bit_bit0_14(3), 0);
set_gpio_mode(GPIOA_bank_bit(3), GPIOA_bit_bit0_14(3), GPIO_OUTPUT_MODE);	
#endif
    msleep(20);
    //LCD3.3V  EIO -> OD0: 1     
#ifdef CONFIG_SN7325
    configIO(0, 0);
    setIO_level(0, 1, 0);
#else
set_gpio_val(GPIOD_bank_bit2_24(20), GPIOD_bit_bit2_24(20), 1);
set_gpio_mode(GPIOD_bank_bit2_24(20), GPIOD_bit_bit2_24(20), GPIO_OUTPUT_MODE);	
#endif    
}

static void set_tcon_pinmux(void)
{
    /* TCON control pins pinmux */
    /* GPIOA_5 -> LCD_Clk, GPIOA_0 -> TCON_STH1, GPIOA_1 -> TCON_STV1, GPIOA_2 -> TCON_OEH, */
    set_mio_mux(0, ((1<<11)|(1<<14)|(1<<15)|(1<<16)));    
    set_mio_mux(4,(1<<0)|(1<<2)|(1<<4));   //For 8bits
    
    //2.6%
    WRITE_CBUS_REG(0x104f, 0x40);
    WRITE_CBUS_REG(0x1058, 0x02);
    WRITE_CBUS_REG(0x1058, READ_CBUS_REG(0x1058)|(1<<8));
}

static void t13_power_on(void)
{
    video_dac_disable();
	set_tcon_pinmux();
	power_on_lcd();
	twx_tc101_reinit();
}
static void t13_power_off(void)
{
	power_off_backlight();
    	power_off_lcd();
}

static void t13_io_init(void)
{
    printk("\n\nGadmei MINILVDS LCD Init.\n\n");
    set_tcon_pinmux();
	t13_power_on();
}

static struct platform_device tcon_dev = {
    .name = "tcon-dev",
    .id   = 0,
    .num_resources = ARRAY_SIZE(tcon_resources),
    .resource      = tcon_resources,
};

static int __init t13_init(void)
{
    t13_setup_gama_table(&tcon_config);
    t13_io_init();

    platform_device_register(&tcon_dev);

    return 0;
}

static void __exit t13_exit(void)
{
    power_off_backlight();
    power_off_lcd();

    platform_device_unregister(&tcon_dev);
}

subsys_initcall(t13_init);
module_exit(t13_exit);

MODULE_DESCRIPTION("AMLOGIC T13 LCD panel driver");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tim Yao <timyao@amlogic.com>");
