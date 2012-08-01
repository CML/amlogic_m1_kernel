
#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
    
#include "hdmi_debug.h"
#include "hdmi_global.h"
    
#include "hdmi_cat_defstx.h"
#include "hdmi_cat_mddc.h"
#include "hdmi_i2c.h"
    
////////////////////////////////////////////////////////////////////////////////
// Function: CAT_ClearDDCFIFO
// Parameter: N/A
// Return: N/A
// Remark: clear the DDC FIFO.
// Side-Effect: DDC master will set to be HOST.
////////////////////////////////////////////////////////////////////////////////
void CAT_ClearDDCFIFO(void) 
{
	
	


////////////////////////////////////////////////////////////////////////////////
// Function: CAT_AbortDDC
// Parameter: N/A
// Return: N/A
// Remark: Force abort DDC and reset DDC bus.
// Side-Effect: 
////////////////////////////////////////////////////////////////////////////////
void CAT_AbortDDC(void) 
{
	
	
	
	    // save the SW reset, DDC master, and CP Desire setting.
	    SWReset = ReadByteHDMITX_CAT(REG_SW_RST);
	
	
	
	WriteByteHDMITX_CAT(REG_SW_RST, SWReset | B_HDCP_RST);	//enable HDCP reset
	WriteByteHDMITX_CAT(REG_DDC_MASTER_CTRL, B_MASTERDDC | B_MASTERHOST);
	
	
		
		
		
			
			
			
		
			
			
			
		
		}
	
	
		
		
		
			
			
			
		
			
			
			    // error when abort.
			    break;
			
		
		}
	
	    // restore the SW reset, DDC master, and CP Desire setting.
//    WriteByteHDMITX_CAT(REG_SW_RST, SWReset) ;
//    WriteByteHDMITX_CAT(REG_HDCP_DESIRE,CPDesire) ;
//    WriteByteHDMITX_CAT(REG_DDC_MASTER_CTRL,DDCMaster) ;
}

{
	
	
