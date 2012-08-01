/*
 ***************************************************************************
 * Ralink Tech Inc.
 * 4F, No. 2 Technology 5th Rd.
 * Science-based Industrial Park
 * Hsin-chu, Taiwan, R.O.C.
 *
 * (c) Copyright 2002-2009, Ralink Technology, Inc.
 *
 * All rights reserved. Ralink's source code is an unpublished work and the
 * use of a copyright notice does not imply otherwise. This source code
 * contains confidential trade secret material of Ralink Tech. Any attemp
 * or participation in deciphering, decoding, reverse engineering or in any
 * way altering the source code is stricitly prohibited, unless the prior
 * written consent of Ralink Technology, Inc. is obtained.
 ***************************************************************************

	Module Name:
	cmm_txbf.c

	Abstract:
	Tx Beamforming related functions

	Revision History:
	Who         When          What
	--------    ----------    ----------------------------------------------
	Shiang     2009/11/04
*/

#include	"rt_config.h"

#ifdef TXBF_SUPPORT
#define ETXBF_PROBE_TIME 500/*500msec*/

UCHAR mcsToLowerMcs[] = {
/*   originalMfb, newMfb1s, newMfb2s, newMfb3s*/
	0,	0,	0,	0,
	1,	1,	1,	1,
	2,	2,	2,	2,
	3,	3,	3,	3,
	4,	4,	4,	4,
	5,	5,	5,	5,
	6,	6,	6,	6,
	7,	7,	7,	7,
	8,	0,	8,	8,
	9,	1,	9,	9,
	10,	2,	10,	10,
	11,	3,	11,	11,
	12,	4,	12,	12,
	13,	5,	13,	13,
	14,	6,	14,	14,
	15,	7,	15,	15,
	16,	0,	8,	16,
	17,	1,	9,	17,
	18,	2,	10,	18,
	19,	3,	11,	19,
	20,	4,	12,	20,
	21,	5,	13,	21,
	22,	6,	14,	22,
	23,	7,	15,	23,
	24,	0,	8,	16,
	25,	1,	9,	17,
	26,	2,	10,	18,
	27,	3,	11,	19,
	28,	4,	12,	20,
	29,	5,	13,	21,
	30,	6,	14,	22,
	31,	7,	15,	23,
	32,	0,	0,	0,
	33,	3,	3,	3,
	34,	3,	3,	3,
	35,	3,	11,	11,
	36,	4,	4,	4,
	37,	6,	6,	6,
	38,	6,	12,	12,
	39,	3,	3,	17,
	40,	3,	11,	11,
	41,	3,	3,	17,
	42,	3,	11,	11,
	43,	3,	11,	19,
	44,	3,	11,	11,
	45,	3,	11,	19,
	46,	4,	4,	18,
	47,	4,	12,	12,
	48,	6,	6,	6,
	49,	6,	12,	12,
	50,	6,	12,	20,
	51,	6,	14,	14,
	52,	6,	14,	14,
	53,	3,	3,	17,
	54,	3,	11,	11,
	55,	3,	11,	19,
	56,	3,	3,	17,
	57,	3,	11,	11,
	58,	3,	11,	19,
	59,	3,	11,	19,
	60,	3,	11,	11,
	61,	3,	11,	19,
	62,	3,	11,	19,
	63,	3,	11,	19,
	64,	3,	11,	19,
	65,	4,	4,	18,
	66,	4,	12,	12,
	67,	4,	12,	20,
	68,	6,	6,	6,
	69,	6,	12,	12,
	70,	6,	12,	20,
	71,	6,	12,	20,
	72,	6,	14,	14,
	73,	6,	14,	14,
	74,	6,	14,	14,
	75,	6,	14,	22,
	76,	6,	14,	22
};
UCHAR groupShift[] = {4, 4, 4}; 
UCHAR groupMethod[] = {0, 0, 0, 0, 0, 0, 0, 0,
						0, 0, 1, 0, 1, 1, 1, 1,
						0, 0, 1, 0, 1, 1, 1, 1};
SHORT groupThrd[] = {-8, 4, 20, 32, 52, 68, 80, 88,
					  -16, 8, 12, 64, 40, 60, 80, 88,
					  -24, 12, 12, 96, 40, 60, 80, 88};
UINT dataRate[] = {65, 130, 195, 260, 390, 520, 585, 650,
				130, 260, 390, 520, 780, 1040, 1170, 1300,
				190, 390, 585, 780, 1170, 1560, 1755, 1950};

/* 4. determine the best method among  mfb0, mfb1, snrComb0, snrComb1*/
/* 5. use the best method. if necessary, sndg with the mcs which resulting in the best snrComb. */

#ifdef CONFIG_AP_SUPPORT
VOID txSndgSameMcs(/*if mcs is not in group 1	*/
	IN	PRTMP_ADAPTER	pAd,
	IN	MAC_TABLE_ENTRY	*pEntry,
	IN	UCHAR smoothMfb)/*smoothMfb should be the current mcs*/
{
	PUCHAR		pTable;
	UCHAR 		TableSize = 0;
	UCHAR		InitTxRateIdx, i, step;
	UCHAR		byteValue = 0;
	UCHAR		SndgType = SNDG_TYPE_SOUNGING; 

	if (pEntry->eTxBfEnCond == 0)
	{
		pEntry->bfState = READY_FOR_SNDG0;
		return;
	}

	/*0. write down the current mfb0*/
	pEntry->mfb0 = smoothMfb;

	/* 1. sndg with current mcs, get snrComb0*/
	/*pEntry->toTxSndg = TRUE;Arvin, please tx a sndg packet when txTxSndg == 1, and then set it to 0!!!*/
	/*Trigger_Sounding_Packet(pAd, 0, pEntry);*/
	if (smoothMfb >> 3 > 0 )
	{
		pEntry->sndgMcs = smoothMfb;
		/*pEntry->ndpSndg = FALSE;*/
	}
	else 
	{
		pEntry->sndgMcs = 8;
		/*pEntry->ndpSndg = TRUE;*/
		SndgType = SNDG_TYPE_NDP;
	}
	/*if ndp sndg is forced by iwpriv command*/
	if (pEntry->ndpSndgStreams == 2 ||pEntry->ndpSndgStreams == 3)
	{
		SndgType = SNDG_TYPE_NDP;
		if (pEntry->ndpSndgStreams == 3)
			pEntry->sndgMcs = 16;
		else 
			pEntry->sndgMcs = 8;
	}

	/*smoothMfb is guaranteed included in the current pTable because it is converted from received MFB in handleHtcField()*/
	APMlmeSelectTxRateTable(pAd, pEntry, &pTable, &TableSize, &InitTxRateIdx);
	if (pTable == RateSwitchTable11N3S) 
		step = 10;
	else 
		step = 5;
	for (i=1; i<=TableSize; i++)
	{
		if (pTable[i*step+2] >= pEntry->sndgMcs)
			break;
	}

	if (i > TableSize)
		i = TableSize - 1;

	/*DBGPRINT(RT_DEBUG_TRACE, ("txSndgSameMcs i = %x, step = %x, sndgMcs = %x CurrentMCS = %x \n",*/
		/*						i, step, pEntry->sndgMcs, pTable[i*step+2]));*/

	pEntry->sndgRateIdx = pTable[i*step];
	if (pEntry->sndgMcs != pTable[i*step+2])
	{
		/*pEntry->sndgMcs = pTable[i*step+2];*/

		if (pTable[i*step+2] > 16)
			pEntry->sndgMcs = 16;
		else if (pTable[i*step+2] > 8)
			pEntry->sndgMcs = 8;
		else
			pEntry->sndgMcs = 0;

		SndgType = SNDG_TYPE_NDP;
	}
		
	/* Enable/disable BF matrix writing*/
	RTMP_BBP_IO_READ8_BY_REG_ID(pAd, BBP_REG_BF, &byteValue);
	if  (pEntry->eTxBfEnCond == 1 || pEntry->eTxBfEnCond == 2)
	{
		byteValue |= 0x80;
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_REG_BF, byteValue);
		pEntry->HTPhyMode.field.eTxBF = 1;			
	}
	else
	{
		byteValue &= (~0x80);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_REG_BF, byteValue);
	}
	
	/* send a sounding packet*/
	Trigger_Sounding_Packet(pAd, SndgType, 0, pEntry->sndgMcs, pEntry);

	RTMPSetTimer(&pEntry->eTxBfProbeTimer, ETXBF_PROBE_TIME);
	DBGPRINT_RAW(RT_DEBUG_TRACE,("ETxBF in txSndgSameMcs(): tx SNDG with the current MCS %d, enter state WAIT_SNDG_FB0\n", pEntry->sndgMcs ));

	pEntry->bfState = WAIT_SNDG_FB0; 
	pEntry->noSndgCnt = 0;	
}

VOID txSndgOtherGroup(	
	IN	PRTMP_ADAPTER	pAd,
	IN	MAC_TABLE_ENTRY	*pEntry)
{
	PUCHAR		pTable;
	UCHAR 		TableSize = 0;
	UCHAR		InitTxRateIdx, i, step;
	UCHAR		byteValue = 0;
	UCHAR		SndgType = SNDG_TYPE_SOUNGING; 

		
	/*tx sndg with mcs in the other group*/
	/*pEntry->toTxSndg = TRUE;Arvin, please tx a sndg when txTxSndg == 1, and then set it to 0!!!*/
	/*Trigger_Sounding_Packet(pAd, 0, pEntry);*/
	if ((pEntry->sndgMcs)>>3 == 2)
	{
		pEntry->sndgMcs = 8;
		/*pEntry->ndpSndg = TRUE;*/
		SndgType = SNDG_TYPE_NDP;
	}
	else
	{
		pEntry->sndgMcs = 16;
		/*pEntry->ndpSndg = TRUE;*/
		SndgType = SNDG_TYPE_NDP;
	}
	/*copied from txSndgSameMcs()*/
	APMlmeSelectTxRateTable(pAd, pEntry, &pTable, &TableSize, &InitTxRateIdx);
	if (pTable == RateSwitchTable11N3S) 
		step = 10;
	else 
		step = 5;
	for (i=1; i<=TableSize; i++)
	{
		if (pTable[i*step+2] >= pEntry->sndgMcs) break;
	}

	if (i > TableSize)
		i = TableSize - 1;

	pEntry->sndgRateIdx = pTable[i*step];

	if (pEntry->sndgMcs != pTable[i*step+2])
	{
		pEntry->sndgMcs = pTable[i*step+2];
		/*pEntry->ndpSndg = TRUE;*/
		SndgType = SNDG_TYPE_NDP;
	}
	/*---copied from txSndgSameMcs() end*/
	/*disable BF matrix writing*/
	RTMP_BBP_IO_READ8_BY_REG_ID(pAd, BBP_REG_BF, &byteValue);
	byteValue &= (~0x80);
	RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_REG_BF, byteValue);
	Trigger_Sounding_Packet(pAd, SndgType, 0, pEntry->sndgMcs, pEntry);

	RTMPSetTimer(&pEntry->eTxBfProbeTimer, ETXBF_PROBE_TIME);
	DBGPRINT_RAW(RT_DEBUG_TRACE,("ETxBF in txSndgOtherGroup(): tx the second SNDG, enter state WAIT_SNDG_FB1\n" ));    		

	pEntry->bfState = WAIT_SNDG_FB1; 		
}

VOID txMrqInvTxBF(
	IN	PRTMP_ADAPTER	pAd,
	IN	MAC_TABLE_ENTRY	*pEntry)

{
	pEntry->toTxMrq = TRUE;
	pEntry->msiToTx = MSI_TOGGLE_BF;

/*	pEntry->HTPhyMode.field.TxBF = ~pEntry->HTPhyMode.field.TxBF;done in another function call*/

	RTMPSetTimer(&pEntry->eTxBfProbeTimer, ETXBF_PROBE_TIME);
	DBGPRINT_RAW(RT_DEBUG_TRACE,("ETxBF in txMrqInvTxBF(): tx the second MRQ, enter state WAIT_MFB\n" ));    		
	pEntry->bfState = WAIT_MFB;
}

UINT convertSnrToThroughput(
	IN UCHAR streamsIn,
	IN int snr0, 
	IN int snr1,
	IN int snr2,
	IN PUCHAR pTable,
	OUT UCHAR *bestMcsPtr,
	OUT UCHAR *bestRateIdxPtr
	
	)
{

	UCHAR streams;
	int	snrTemp;
	UCHAR 	i, j;
	SHORT idx;
	SHORT group;
 	int	snrTemp1[3];
	int snr[] = {snr0, snr1, snr2};
	int snrSum, tpTemp, bestTp=0;
	SHORT thrdTemp;
	BOOLEAN isMcsValid[24];
	UCHAR	rateIdx[24], step, tableSize;
	UCHAR mcs;

	if (pTable == RateSwitchTable11N3S) 
		step = 10;
	else 
		step = 5;
	tableSize = pTable[0];
	for (i=0; i<24; i++)
	{
		isMcsValid[i] = FALSE;
		rateIdx[i] = 0;
	}
	for (i=1; i<=tableSize; i++)
	{
		isMcsValid[pTable[i*step+2]] = TRUE;
		rateIdx[pTable[i*step+2]] = pTable[i*step];
	}
	
	if (streamsIn > 3)
	{
		DBGPRINT_RAW(RT_DEBUG_TRACE,("convertSnrToThroughput(): %d streams are not supported!!!", streamsIn));			
		streams = 3;
	}
	else
		streams = streamsIn;
		
	for (i=0; i<streams; i++){
		for (j=i+1; j<streams; j++){
			if (snr[i] < snr[j]){
				snrTemp = snr[i];
				snr[i] = snr[j];
				snr[j] = snrTemp;
			}
		}
	}
	(*bestMcsPtr) = 0;
	(*bestRateIdxPtr) = rateIdx[0];	
	for (group=streams-1; group >=0; group--)
	{
		snrTemp1[0] = snr[0];
		snrTemp1[1] = snr[1];
		snrTemp1[2] = snr[2];
		/*SNR processing for each group according to the baseband implementation, for example MRC*/
		switch (group)
		{
			case 0:
				snrTemp1[1] = 0;
				snrTemp1[2] = 0;
				break;
			case 1:
				snrTemp1[2] = 0;
				break;
			case 2:
				break;
			default:
				break;
		}
		snrSum = snr[0] + snr[1] + snr[2];
		for (idx=7; idx>=0; idx--){
			mcs = group*8+idx;
			thrdTemp = groupThrd[mcs];
			tpTemp = 0;
			if (groupMethod[mcs] == 0)
			{
				if (snrSum > thrdTemp)
					tpTemp =  ((snrSum - thrdTemp) * dataRate[mcs])>>groupShift[group];
			}
			else 
			{
				if (group == 1)
					snrTemp1[2] = thrdTemp + 1;
				if (snrTemp1[0] > thrdTemp && snrTemp1[1] > thrdTemp && snrTemp1[2] > thrdTemp)
					tpTemp = ((snrTemp1[0] - thrdTemp)*(snrTemp1[1] - thrdTemp)*(snrTemp1[2] - thrdTemp) * dataRate[mcs])>>groupShift[group];/* have to be revised!!!*/
			}
			if (tpTemp > dataRate[mcs])
				tpTemp = dataRate[mcs];
			if (tpTemp > bestTp && isMcsValid[mcs] == TRUE)
			{
				bestTp = tpTemp;
				(*bestMcsPtr) = mcs;
				(*bestRateIdxPtr) = rateIdx[mcs];
	DBGPRINT_RAW(RT_DEBUG_TRACE,("convertSnrToThroughput(): new candidate snr0=%d, snr1=%d, snr2=%d, tp=%d, best MCS=%d\n", snrTemp1[0], snrTemp1[1], snrTemp1[2], tpTemp, *bestMcsPtr));			
			}
		}
	}
	DBGPRINT_RAW(RT_DEBUG_TRACE,("convertSnrToThroughput(): snr0=%d, snr1=%d, snr2=%d, tp=%d, best MCS=%d\n", snr0, snr1, snr2, bestTp, *bestMcsPtr));			
	return bestTp;
	}			

VOID chooseBestMethod(	
	IN	PRTMP_ADAPTER	pAd,
	IN	MAC_TABLE_ENTRY	*pEntry,
	IN	UCHAR			mfb)
{
/*	UCHAR bestMethod;0:original, 1:inverted TxBF, 2:first sndg, 3:second sndg*/
	UINT tp[4], bestTp;
	UCHAR streams, i;
	PUCHAR		pTable;
	UCHAR 		TableSize = 0;
	UCHAR		InitTxRateIdx;
	UCHAR		byteValue = 0;

	pEntry->mfb1 = mfb;
	DBGPRINT_RAW(RT_DEBUG_TRACE,("ETxBF in chooseBestMethod(): received the second MFB %d, noted as mfb1\n", pEntry->mfb1 ));    	
	
	if ((pAd->MACVersion == RALINK_2883_VERSION &&pEntry->HTCapability.MCSSet[2] == 0xff && pAd->CommonCfg.TxStream == 3))
	{
		streams = 3;
	} 
	else if (pEntry->HTCapability.MCSSet[0] == 0xff && pEntry->HTCapability.MCSSet[1] == 0xff && pAd->CommonCfg.TxStream > 1 
		 	      && (pAd->CommonCfg.TxStream == 2 || pEntry->HTCapability.MCSSet[2] == 0x0))
	{
		streams = 2;
	} 
	else
	{
		streams = 1;
	}

	APMlmeSelectTxRateTable(pAd, pEntry, &pTable, &TableSize, &InitTxRateIdx);

	 tp[2] = convertSnrToThroughput(streams, pEntry->sndg0Snr0,  pEntry->sndg0Snr1, pEntry->sndg0Snr2, pTable, &(pEntry->bf0Mcs), &(pEntry->bf0RateIdx));
	 tp[3] = convertSnrToThroughput(streams, pEntry->sndg1Snr0,  pEntry->sndg1Snr1, pEntry->sndg1Snr2, pTable, &(pEntry->bf1Mcs), &(pEntry->bf1RateIdx));
	 tp[0] = dataRate[pEntry->mfb0];
	 tp[1] = dataRate[pEntry->mfb1];
	 bestTp = 0;
	 for (i=0; i<4; i++)
	 {
		DBGPRINT_RAW(RT_DEBUG_TRACE,("ETxBF in chooseBestMethod(): predicted throughput of method %d = %d\n", i, tp[i] ));    	
	 	if (tp[i] > bestTp)
		{
			bestTp = tp[i];
			pEntry->bestMethod = i;	
	 	}
	 }
	DBGPRINT_RAW(RT_DEBUG_TRACE,("ETxBF in chooseBestMethod(): method %d is chosen\n", pEntry->bestMethod ));    	
	 switch (pEntry->bestMethod)
	 {
	 	case 0:/*do nothing*/
			pEntry->bfState = READY_FOR_SNDG0;
			DBGPRINT_RAW(RT_DEBUG_TRACE,("ETxBF in chooseBestMethod(): do nothing, and enter state READY_FOR_SNDG0\n" ));    	
			break;
	 	case 1:
			pEntry->HTPhyMode.field.eTxBF = ~pEntry->HTPhyMode.field.eTxBF;/*arvin, please make sure the TxBF status is indeed inverted afterwards!!!*/
			pEntry->bfState = READY_FOR_SNDG0;
			DBGPRINT_RAW(RT_DEBUG_TRACE,("ETxBF in chooseBestMethod(): invert the ETxBF status, and enter state READY_FOR_SNDG0\n" ));    	
			break;
	 	case 2:
			/*pEntry->toTxSndg = TRUE;Arvin, please tx a sndg packet when txTxSndg == 1, and then set it to 0!!!*/
			pEntry->sndgMcs = pEntry->sndg0Mcs;
			pEntry->sndgRateIdx = pEntry->sndg0RateIdx;
			/*enable BF matrix writing*/
			RTMP_BBP_IO_READ8_BY_REG_ID(pAd, BBP_REG_BF, &byteValue);
			byteValue |= 0x80;
			RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_REG_BF, byteValue);
			if (pEntry->sndgRateIdx == pEntry->CurrTxRateIndex)
				Trigger_Sounding_Packet(pAd, SNDG_TYPE_SOUNGING, 0, pEntry->sndgMcs, pEntry);
			else
				Trigger_Sounding_Packet(pAd, SNDG_TYPE_NDP, 0, pEntry->sndgMcs, pEntry);			
			RTMPSetTimer(&pEntry->eTxBfProbeTimer, ETXBF_PROBE_TIME);
			DBGPRINT_RAW(RT_DEBUG_TRACE,("ETxBF in chooseBestMethod(): tx the SNDG of the best method, enter state WAIT_BEST_SNDG\n" ));    	
			pEntry->bfState = WAIT_BEST_SNDG;
			break;
	 	case 3:
			/*tx sndg with mcs in the other group*/
			/*pEntry->toTxSndg = TRUE;Arvin, please tx a sndg when txTxSndg == 1, and then set it to 0!!!*/
			pEntry->sndgMcs = pEntry->sndg1Mcs;
			pEntry->sndgRateIdx = pEntry->sndg1RateIdx;
			/*enable BF matrix writing*/
			RTMP_BBP_IO_READ8_BY_REG_ID(pAd, BBP_REG_BF, &byteValue);
			byteValue |= 0x80;
			RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_REG_BF, byteValue);
			if (pEntry->sndgRateIdx == pEntry->CurrTxRateIndex)
				Trigger_Sounding_Packet(pAd, SNDG_TYPE_SOUNGING, 0, pEntry->sndgMcs, pEntry);
			else
				Trigger_Sounding_Packet(pAd, SNDG_TYPE_NDP, 0, pEntry->sndgMcs, pEntry);
			RTMPSetTimer(&pEntry->eTxBfProbeTimer, ETXBF_PROBE_TIME);
			DBGPRINT_RAW(RT_DEBUG_TRACE,("ETxBF in chooseBestMethod(): tx the SNDG of the best method, enter state WAIT_BEST_SNDG\n" ));    	
			pEntry->bfState = WAIT_BEST_SNDG;
			break;
	 }
}

VOID rxBestSndg(
	IN	PRTMP_ADAPTER	pAd,
	IN	MAC_TABLE_ENTRY	*pEntry)
{
	/*set the best mcs of this BF matrix*/
	if (pEntry->bestMethod == 2)
	{
		pEntry->CurrTxRate = pEntry->bf0Mcs;
		pEntry->CurrTxRateIndex = pEntry->bf0RateIdx;
	}
	else if (pEntry->bestMethod == 3)
	{
		pEntry->CurrTxRate = pEntry->bf1Mcs;
		pEntry->CurrTxRateIndex = pEntry->bf1RateIdx;
	}
	pEntry->HTPhyMode.field.eTxBF = 1;
	
	/*must sync the timing of using new BF matrix and its bfRateIdx!!!*/
	/*need to reset counter for rateAdapt and may have to skip one adaptation when the new BF matrix is applied!!!*/

	DBGPRINT_RAW(RT_DEBUG_TRACE,("ETxBF in rxBestSndg(): received the feedback of the best SNDG, and enter state READY_FOR_SNDG0\n" ));    	

	pEntry->bfState = READY_FOR_SNDG0;		
}

VOID handleBfFb(
	IN	PRTMP_ADAPTER	pAd,
	IN	RX_BLK			*pRxBlk)
{
	PRXWI_STRUC		pRxWI = pRxBlk->pRxWI;
	MAC_TABLE_ENTRY	*pEntry = NULL;		
	pEntry = PACInquiry(pAd, pRxWI->WirelessCliID);	
	DBGPRINT_RAW(RT_DEBUG_TRACE,("ETxBF in handleBfFb(): receive sounding response\n")); 

	DBGPRINT(RT_DEBUG_TRACE, ("ETxBF :(%02x:%02x:%02x:%02x:%02x:%02x)\n", 
		pEntry->Addr[0],pEntry->Addr[1],pEntry->Addr[2],pEntry->Addr[3],pEntry->Addr[4], pEntry->Addr[5]));

	
	if (pEntry->bfState == WAIT_SNDG_FB0)
	{
		int Nc = ((pRxBlk ->pData)[2] & 0x3) + 1;
		/*record the snr comb*/
		pEntry->sndg0Snr0 = 88+(CHAR)(pRxBlk ->pData[8]);
		pEntry->sndg0Snr1 = (Nc<2)? 0: 88+(CHAR)(pRxBlk ->pData[9]);
		pEntry->sndg0Snr2 = (Nc<3)? 0: 88+(CHAR)(pRxBlk ->pData[10]);
		pEntry->sndg0Mcs = pEntry->sndgMcs;

		DBGPRINT_RAW(RT_DEBUG_TRACE,("ETxBF in handleBfFb(): %02x %02x %02x %02x %02x %02x\n", (pRxBlk ->pData)[2],  (pRxBlk ->pData)[3],  (pRxBlk ->pData)[4],  (pRxBlk ->pData)[5],  (pRxBlk ->pData)[6],  (pRxBlk ->pData)[7]));
		DBGPRINT_RAW(RT_DEBUG_TRACE,("ETxBF in handleBfFb(): mcs%d, snr %d  %d %d\n", pEntry->sndg0Mcs,  pEntry->sndg0Snr0, pEntry->sndg0Snr1, pEntry->sndg0Snr2 ));    		
			if (pEntry->eTxBfEnCond == 1 ||pEntry->eTxBfEnCond == 2)
				pEntry->bfState =READY_FOR_SNDG0;
	     		/* 2. sndg with current mcs+8 or -8, get snrComb1*/
	     		else if (pEntry->eTxBfEnCond == 3)
				txSndgOtherGroup(pAd, pEntry);
	} 
	else if (pEntry->bfState == WAIT_SNDG_FB1) 
	{
		
	     	/* 3. mrq with inverted TxBF status, get mfb1*/
	     	if (TRUE)
		{/*Arvin, please replace this by the condition that mrq and mfb are supported!!!*/
			int Nc = ((pRxBlk ->pData)[2] & 0x3) + 1;
			/*record the snr comb*/
			pEntry->sndg0Snr0 = 88+(CHAR)(pRxBlk ->pData[8]);
			pEntry->sndg0Snr1 = (Nc<2)? 0: 88+(CHAR)(pRxBlk ->pData[9]);
			pEntry->sndg0Snr2 = (Nc<3)? 0: 88+(CHAR)(pRxBlk ->pData[10]);
			pEntry->sndg1Mcs = pEntry->sndgMcs;

			DBGPRINT_RAW(RT_DEBUG_TRACE,("ETxBF in handleBfFb(): %d %d %d %d %d %d\n", (pRxBlk ->pData)[2],  (pRxBlk ->pData)[3],  (pRxBlk ->pData)[4],  (pRxBlk ->pData)[5],  (pRxBlk ->pData)[6],  (pRxBlk ->pData)[7]));    		
			DBGPRINT_RAW(RT_DEBUG_TRACE,("ETxBF in handleBfFb(): mcs%d, snr %d  %d %d\n",  pEntry->sndg1Mcs, pEntry->sndg1Snr0, pEntry->sndg1Snr1, pEntry->sndg1Snr2 ));    					
			txMrqInvTxBF(pAd,  pEntry);
	     	}
		else
			chooseBestMethod(pAd, pEntry, 0);
	} 
	else if (pEntry->bfState == WAIT_USELESS_RSP)
	{
		int Nc = ((pRxBlk ->pData)[2] & 0x3) + 1;
		pEntry->sndg0Snr0 = 88+(CHAR)(pRxBlk ->pData[8]);
		pEntry->sndg0Snr1 = (Nc<2)? 0: 88+(CHAR)(pRxBlk ->pData[9]);
		pEntry->sndg0Snr2 = (Nc<3)? 0: 88+(CHAR)(pRxBlk ->pData[10]);
		DBGPRINT_RAW(RT_DEBUG_TRACE,("ETxBF in handleBfFb(): %d %d %d %d %d %d\n", (pRxBlk ->pData)[2],  (pRxBlk ->pData)[3],  (pRxBlk ->pData)[4],  (pRxBlk ->pData)[5],  (pRxBlk ->pData)[6],  (pRxBlk ->pData)[7]));    		
		DBGPRINT_RAW(RT_DEBUG_TRACE,("ETxBF in handleBfFb(): mcs%d, snr %d  %d %d\n",  pEntry->sndg1Mcs, pEntry->sndg1Snr0, pEntry->sndg1Snr1, pEntry->sndg1Snr2 ));    		
		txSndgSameMcs(pAd, pEntry, /*pRxBlk,*/ pEntry->lastLegalMfb);
	} 
	else if (pEntry->bfState == WAIT_BEST_SNDG)
	{

		rxBestSndg(pAd, pEntry);
	}
}

VOID handleHtcField(
	IN	PRTMP_ADAPTER	pAd,
	IN	RX_BLK			*pRxBlk)
{
	UCHAR				mfb = ((PHT_CONTROL)(pRxBlk->pData))-> MFBorASC;
	UCHAR				mfsi = ((PHT_CONTROL)(pRxBlk->pData))-> MFSI;
	UCHAR				legalMfb = 0, legalMfbIdx=0, smoothMfb = 0;
	PRXWI_STRUC		pRxWI = pRxBlk->pRxWI;
	MAC_TABLE_ENTRY	*pEntry = NULL;	
	UCHAR				i, j;
	PUCHAR					pTable;
	UCHAR					TableSize = 0;	
	UCHAR					InitTxRateIdx;
	PRTMP_TX_RATE_SWITCH_3S	pLegalMfbRS3S = NULL;
	PRTMP_TX_RATE_SWITCH	pLegalMfbRS = NULL;
	UCHAR 				snr[] = {pRxWI->SNR0, pRxWI->SNR1, pRxWI->SNR2};
	UCHAR				snrTemp1[3];
	UCHAR				snrTemp;
	UCHAR				streams;
	UINT			tpTemp, bestTp = 0, snrSum;
	SHORT			thrdTemp;
	SHORT 			group, idx;
	UCHAR			mcs;
	
	pEntry = PACInquiry(pAd, pRxWI->WirelessCliID);	
	/*if MFB is received*/
	/*have to rule out the case when mai==14*/
	if (!(((PHT_CONTROL)(pRxBlk->pData))->MRQ == 0 && ((PHT_CONTROL)(pRxBlk->pData))->MSI == 7) 
		 && mfb != 127)
	{/*need a timer in case there is no mfb with this mfsi*/
		DBGPRINT_RAW(RT_DEBUG_INFO, ("	MFB in handleHtcField(): MFB %d is received\n", mfb));
		/*check if the mfb is valid. if not, convert to a valid mcs*/
		if (mfb > 76)
			DBGPRINT_RAW(RT_DEBUG_TRACE, ("Error in handleHtcField: received MFB > 76\n"));

		if (pEntry->HTCapability.MCSSet[0] == 0xff && pEntry->HTCapability.MCSSet[1] == 0xff 
			     && pEntry->HTCapability.MCSSet[2] == 0xff && pAd->CommonCfg.TxStream == 3)
			legalMfb = mcsToLowerMcs[4*mfb + 3];
		else if (pEntry->HTCapability.MCSSet[0] == 0xff && pEntry->HTCapability.MCSSet[1] == 0xff && pAd->CommonCfg.TxStream > 1 
  		 	      && (pAd->CommonCfg.TxStream == 2 || pEntry->HTCapability.MCSSet[2] == 0x0))			
			legalMfb = mcsToLowerMcs[4*mfb + 2];
		else if (pEntry->HTCapability.MCSSet[0] == 0xff &&( pAd->CommonCfg.TxStream == 1 ||pEntry->HTCapability.MCSSet[1] == 0x0))
			legalMfb = mcsToLowerMcs[4*mfb + 1];
		else
			DBGPRINT_RAW(RT_DEBUG_TRACE, ("no available MFB mapping for the received MFB\n"));
		/*have to rule out the mfb that the Rx shouldn't be able to suggest??? for example, mrq was sent with 2 streams but the Rx suggests MCS with 3 streams*/


		if ( mfsi == MSI_TOGGLE_BF)
		{

			 if (pEntry->bfState == WAIT_MFB)
				chooseBestMethod(pAd,  pEntry, legalMfb);
			 else if (pEntry->bfState == WAIT_USELESS_RSP)
				txSndgSameMcs(pAd, pEntry,/* pRxBlk,*/ legalMfb);
		}
	}
	
	if (!(((PHT_CONTROL)(pRxBlk->pData))->MRQ == 0 && ((PHT_CONTROL)(pRxBlk->pData))->MSI == 7 && mfsi != MSI_TOGGLE_BF) 
		 && mfb != 127)
	{

		/*the main body of algorithm*/
		/*legalMfb smoothing*/
		APMlmeSelectTxRateTable(pAd, pEntry, &pTable, &TableSize, &InitTxRateIdx);	
		/*it's required that the station supporting MFB will result in that RateSwitchTable11N3S is chosen!!!*/
		if (pTable != RateSwitchTable11N3S)
		{
			for (i=1; i<=pTable[0]; i++)
			{
				if (legalMfb == pTable[i*5+2])
				{
					legalMfbIdx = pTable[i*5];
					pLegalMfbRS = (PRTMP_TX_RATE_SWITCH) &pTable[i*5]; 			
					break;
				}
			}		
			if ((pEntry->lastLegalMfb <= legalMfb+1 || pEntry->lastLegalMfb+1 >= legalMfb) && ((legalMfb>>3) == (pEntry->lastLegalMfb >>3)))
			    	smoothMfb = pEntry->lastLegalMfb;
			else
				smoothMfb = legalMfb;
		} 
		else 
		{
			for (i=1; i<=pTable[0]; i++)
			{
				if (legalMfb == pTable[i*10+2])
				{
					legalMfbIdx = pTable[i*10];
					pLegalMfbRS3S = (PRTMP_TX_RATE_SWITCH_3S) &pTable[i*10]; 			
					pLegalMfbRS = (PRTMP_TX_RATE_SWITCH) &pTable[i*10]; 			
					break;
				}
			}	
			/*pLegalMfbRS3S may be null if pLegalMfbRS3S is not found!!!*/
			if (pEntry->lastLegalMfb == pTable[(pLegalMfbRS3S->downMcs+1)*10+2] ||pEntry->lastLegalMfb == pTable[(pLegalMfbRS3S->upMcs1+1)*10+2]
			    ||pEntry->lastLegalMfb == pTable[(pLegalMfbRS3S->upMcs2+1)*10+2] ||pEntry->lastLegalMfb == pTable[(pLegalMfbRS3S->upMcs3+1)*10+2])
			    	smoothMfb = pEntry->lastLegalMfb;
			else
				smoothMfb = legalMfb;
		}

			
			if (smoothMfb != pEntry->lastLegalMfb && smoothMfb != pTable[(pEntry->CurrTxRateIndex+1)*10+2])
			{/*if mfb changes and mfb is different from current mcs: means channel change*/
				if ((pAd->MACVersion == RALINK_2883_VERSION &&pEntry->HTCapability.MCSSet[2] == 0xff && pAd->CommonCfg.TxStream == 3))
					pEntry->mcsGroup = 3;/*ys*/
				 else if (pEntry->HTCapability.MCSSet[0] == 0xff && pEntry->HTCapability.MCSSet[1] == 0xff && pAd->CommonCfg.TxStream > 1 
			 	    		 && (pAd->CommonCfg.TxStream == 2 || pEntry->HTCapability.MCSSet[2] == 0x0))
			 	      pEntry->mcsGroup = 2;
				 else
					pEntry->mcsGroup = 1;
				pEntry->CurrTxRateIndex = legalMfbIdx;
				NdisZeroMemory(pEntry->TxQuality, sizeof(USHORT) * MAX_STEP_OF_TX_RATE_SWITCH);/*clear all history, same as train up, purpose???*/
				NdisZeroMemory(pEntry->PER, sizeof(UCHAR) * MAX_STEP_OF_TX_RATE_SWITCH);/*clear all history, same as train up, purpose???*/
				NdisAcquireSpinLock(&pEntry->fLastChangeAccordingMfbLock);
				/*APMlmeSetTxRate(pAd, pEntry, pLegalMfbRS);*/
				NdisMoveMemory(pEntry->LegalMfbRS, pLegalMfbRS, sizeof(PRTMP_TX_RATE_SWITCH));
				pEntry->fLastChangeAccordingMfb = TRUE;
				/* reset all OneSecTx counters*/
				/*RESET_ONE_SEC_TX_CNT(pEntry);*/
				NdisReleaseSpinLock(&pEntry->fLastChangeAccordingMfbLock);
				DBGPRINT_RAW(RT_DEBUG_INFO,("	MFB in handleHtcField(): MFB changes and use the new mfb=%d, mfbIdx=%d\n", legalMfb, legalMfbIdx));			
	/*			pEntry->isMfbChanged = TRUE;*/

				if ((pEntry->HTCapability.TxBFCap.ExpNoComBF && pAd->CommonCfg.HtCapability.TxBFCap.TxSoundCapable 
				     && pAd->CommonCfg.HtCapability.TxBFCap.ExpNoComSteerCapable))
				{/*support ETxBF. what's the correct criterion????*/
				     	/*the process is triggered by channel change here. have to add the mechanism where the process is triggered by timer expiration!!!*/
					if (pEntry->eTxBfEnCond == 3)
					{
					     	if (pEntry->bfState == READY_FOR_SNDG0)	
						{
							DBGPRINT_RAW(RT_DEBUG_OFF,("ETxBF in handleHtcField(): detect MFB change, set pEntry->mfb0=%d\n", pEntry->mfb0 ));    	
							txSndgSameMcs(pAd, pEntry, /*pRxBlk,*/ legalMfb);
						} 
						else
						{
							DBGPRINT_RAW(RT_DEBUG_TRACE,("ETxBF in handleHtcField(): detect channel change before enter the ETxBF probe process is complete, enter state WAIT_USELESS_RSP\n" ));    			
							pEntry->bfState = WAIT_USELESS_RSP;
						}
					}

					/*write down the current MFB and ixTxBF. currentMFB is recorded in lastLegalMfb*/
					 /*send one packet with reverse TxBF, 2 stream sounding*/
				}
				
			}

		/*post-prossessing*/
		if (pEntry->fLastChangeAccordingMfb)
			pEntry->lastLegalMfb = legalMfb;
	}


	/*if mrq is received*/
	if (((PHT_CONTROL)(pRxBlk->pData))->MRQ == 1)
	{
		DBGPRINT_RAW(RT_DEBUG_INFO, ("	MFB in handleHtcField(): MRQ is received\n"));
		/*assumption: snr are not sorted, wait for John or Julian's answer as to the SNR values of unused streams*/
		if ((pAd->MACVersion == RALINK_2883_VERSION &&pEntry->HTCapability.MCSSet[2] == 0xff && pAd->CommonCfg.TxStream == 3))
		{
			streams = 3;
		} 
		else if (pEntry->HTCapability.MCSSet[0] == 0xff && pEntry->HTCapability.MCSSet[1] == 0xff && pAd->CommonCfg.TxStream > 1 
			 	      && (pAd->CommonCfg.TxStream == 2 || pEntry->HTCapability.MCSSet[2] == 0x0))
		{
			streams = 2;
		} 
		else
		{
			streams = 1;
		}
		/*sort such that snr[0]>=snr[1]>=snr[2]. sorting is required for group 2 so that the best 2 streams are used.*/
		for (i=0; i<streams; i++)
		{
			for (j=i+1; j<streams; j++)
			{
				if (snr[i] < snr[j])
				{
					snrTemp = snr[i];
					snr[i] = snr[j];
					snr[j] = snrTemp;
				}
			}
		}
		for (group=streams-1; group >=0; group--)
		{
			snrTemp1[0] = snr[0];
			snrTemp1[1] = snr[1];
			snrTemp1[2] = snr[2];
			/*SNR processing for each group according to the baseband implementation, for example MRC*/
			switch (group)
			{
				case 0:
					snrTemp1[1] = 0;
					snrTemp1[2] = 0;
					break;
				case 1:
					snrTemp1[2] = 0;
					break;
				case 2:
					break;
				default:
					break;
			}
			snrSum = snr[0] + snr[1] + snr[2];
			for (idx=8; idx>=1; idx--){
				mcs = group*8+idx-1;
				thrdTemp = groupThrd[mcs];
				tpTemp = 0;
				if (groupMethod[mcs] == 0)
				{
					if (snrSum > thrdTemp)
					tpTemp =  ((snrSum - thrdTemp) * dataRate[mcs])>>groupShift[group];
				}
				else 
				{
					if (group == 1)
						snrTemp1[2] = thrdTemp + 1;
					if (snrTemp1[0] > thrdTemp && snrTemp1[1] > thrdTemp && snrTemp1[2] > thrdTemp)
						tpTemp = ((snrTemp1[0] - thrdTemp)*(snrTemp1[1] - thrdTemp)*(snrTemp1[2] - thrdTemp) * dataRate[mcs])>>groupShift[group];/* have to be revised!!!			*/
				}
				if (tpTemp > dataRate[mcs])
					tpTemp = dataRate[mcs];
				if (tpTemp > bestTp)
				{
					bestTp = tpTemp;
					pEntry->mfbToTx = mcs;
				}
				
			}
		}
		pEntry->toTxMfb = 1;/*should be reset to 0 when mfb is actually sent out!!!*/
		DBGPRINT_RAW(RT_DEBUG_INFO,("	MFB in handleHtcField(): MFB %d is going to be sent\n", pEntry->mfbToTx));			
		
		
	}
}

void eTxBfProbeTimerExec(
    IN PVOID SystemSpecific1, 
    IN PVOID FunctionContext, 
    IN PVOID SystemSpecific2, 
    IN PVOID SystemSpecific3) 
{
	MAC_TABLE_ENTRY     *pEntry = (PMAC_TABLE_ENTRY) FunctionContext;
	PRTMP_ADAPTER pAd = (PRTMP_ADAPTER)pEntry->pAd;
	if (pEntry->bfState == WAIT_SNDG_FB0)
	{
		/*record the snr comb*/
		pEntry->sndg0Snr0 = -128;
		pEntry->sndg0Snr1 = -128;
		pEntry->sndg0Snr2 = -128;
		pEntry->sndg0Mcs = pEntry->sndgMcs;
		DBGPRINT_RAW(RT_DEBUG_TRACE,("ETxBF in eTxBfProbeTimerExec(): timer of WAIT_SNDG_FB0 expires, run txSndgOtherGroup()\n" ));    	
			if (pEntry->eTxBfEnCond == 1 || pEntry->eTxBfEnCond == 2)
				pEntry->bfState =READY_FOR_SNDG0;
			else if (pEntry->eTxBfEnCond == 3)
				txSndgOtherGroup(pAd, pEntry);
	}
	else if (pEntry->bfState == WAIT_SNDG_FB1)
	{
		/*record the snr comb*/
		pEntry->sndg1Snr0 = -128;
		pEntry->sndg1Snr1 = -128;
		pEntry->sndg1Snr2 = -128;
		pEntry->sndg1Mcs = pEntry->sndgMcs;
		DBGPRINT_RAW(RT_DEBUG_TRACE,("ETxBF in eTxBfProbeTimerExec(): timer of WAIT_SNDG_FB1 expires, run txMrqInvTxBF()\n" ));    	
		txMrqInvTxBF(pAd, pEntry);
	
	}
	else if (pEntry->bfState == WAIT_MFB)
	{
		DBGPRINT_RAW(RT_DEBUG_TRACE,("ETxBF in eTxBfProbeTimerExec(): timer of WAIT_MFB expires, run chooseBestMethod()\n" ));    	
		chooseBestMethod(pAd, pEntry, 0);
	}
	else if (pEntry->bfState == WAIT_BEST_SNDG)
	{
		DBGPRINT_RAW(RT_DEBUG_TRACE,("ETxBF in eTxBfProbeTimerExec(): timer of WAIT_BEST_SNDG expires, run rxBestSndg()\n" ));    	
		rxBestSndg(pAd, pEntry);
	}
/*	pEntry->bfState = READY_FOR_SNDG0;*/

}

VOID MFB_PerPareMRQ(
	IN	PRTMP_ADAPTER	pAd,
	OUT	VOID* pBuf,
	IN	PMAC_TABLE_ENTRY pEntry)
{
	PHT_CONTROL pHT_Control;

/*	DBGPRINT(RT_DEBUG_TRACE, ("-----> MFB_PerPareMRQ\n"));*/
	if (pEntry->HTCapability.ExtHtCapInfo.MCSFeedback >= MCSFBK_MRQ)
	{
		pHT_Control = (HT_CONTROL *)pBuf;

		pHT_Control->MRQ = 1;
		
		if (pEntry->msiToTx == MSI_TOGGLE_BF)
			if (pEntry->mrqCnt == 0)
				pEntry->mrqCnt = TOGGLE_BF_PKTS;
			else 
			{
				(pEntry->mrqCnt)--;
				if (pEntry->mrqCnt == 0)
					pEntry->msiToTx = 0;
			}
		pHT_Control->MSI = pEntry->msiToTx;

		/*update region*/
		if (pEntry->msiToTx == MSI_TOGGLE_BF-1)/*MSI_TOGGLE_BF==6 is used to indicate the TxBF status is inverted for this packet*/
			pEntry->msiToTx = 0;
		else if (pEntry->msiToTx !=  MSI_TOGGLE_BF)
			pEntry->msiToTx++;

	}

/*	DBGPRINT(RT_DEBUG_TRACE, ("<----- MFB_PerPareMRQ\n"));*/
}

VOID MFB_PerPareMFB(/*to be completed!!!!!!!!!!!!!!!!!*/
	IN	PRTMP_ADAPTER	pAd,
	OUT	VOID* pBuf,
	IN	PMAC_TABLE_ENTRY pEntry)
{
	PHT_CONTROL pHT_Control;

/*	DBGPRINT(RT_DEBUG_TRACE, ("-----> MFB_PerPareMRQ\n"));*/
/*	if (pAd->CommonCfg.HtCapability.ExtHtCapInfo.MCSFeedback >= MCSFBK_MRQ)
	{
		pHT_Control = (HT_CONTROL *)pBuf;

		pHT_Control-> = 1;
		
		if (pEntry->msiToTx == MSI_TOGGLE_BF)
			if (pEntry->mrqCnt == 0)
				pEntry->mrqCnt = TOGGLE_BF_PKTS;
			else 
			{
				(pEntry->mrqCnt)--;
				if (pEntry->mrqCnt == 0)
					pEntry->msiToTx = 0;
			}
		pHT_Control->MFBorASC = ;
		pHT_Control->MFSI = 

		/*update region*/
		if (pEntry->msiToTx == MSI_TOGGLE_BF-1)/*MSI_TOGGLE_BF==6 is used to indicate the TxBF status is inverted for this packet*/
			pEntry->msiToTx = 0;
		else if (pEntry->msiToTx !=  MSI_TOGGLE_BF)
			pEntry->msiToTx++;

}				
*/
/*	DBGPRINT(RT_DEBUG_TRACE, ("<----- MFB_PerPareMRQ\n"));*/
}
#endif /* CONFIG_AP_SUPPORT */

#endif /* TXBF_SUPPORT */


