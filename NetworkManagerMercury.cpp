/********************************************************************/
/*                                                                  */
/* Copyright Avaya Inc.                                             */
/*                                                                  */
/********************************************************************/
#include "NetworkManager.h"
#include "message/MessageCategory.h"
#include "message/API.h"
#include "core/Log.h"
#include "core/File.h"
#include "core/StrTokenizer.h"
#include "common/ReturnCodes.h"
#include "common/Definitions.h"
#include "adaptor/network/BasePacketFilterAdaptor.h"
#include "adaptor/network/test/TestNetworkAdaptor.h"

#if defined (PLATFORM_WINDOWS)
#include "adaptor/network/windows/WinNetworkAdaptor.h"
#include "adaptor/network/linux/UnixWiFiEmulatorAPI.h"
#include "adaptor/network/linux/UnixWiFiEmulatorAPI.inc"
#elif defined (PLATFORM_VXWORKS)
#include "adaptor/network/vxworks/VxNetworkAdaptor.h"
#include "adaptor/network/vxworks/VxPacketFilterAdaptor.h"
#include "adaptor/network/vxworks/VlanUtils.h"
#elif defined (FEATURE_WIFI) && defined(IPPCFG_DVF99)
#include "adaptor/network/linux/UnixEthernetNetworkAdaptor.h"
#if !defined (WIFI_EMULATION_ONLY)
#include "adaptor/network/linux/UnixWiFiEmulatorAPI.inc"
#endif
#elif defined (PLATFORM_MACOSX) || defined (PLATFORM_IPHONE)
#include "adaptor/network/mac/MacNetworkAdaptor.h"
#endif
#if defined(IPPCFG_BCM1108) || defined(IPPCFG_DVF99)
#include "adaptor/network/linux/UnixVlanUtilsInterface.h"
#include "adaptor/network/linux/LinuxPacketFilterAdaptor.h"
#include <stdio.h>
#include <dirent.h>
#endif
   
#if defined(PLATFORM_ANDROID)	//New for SUMMIT  
#include "adaptor/network/linux/UnixVlanUtilsInterface.h"
#include "adaptor/network/linux/LinuxPacketFilterAdaptor.h"
#endif

#include "manager/adaptor/AdaptorManager.h"
#include "manager/message/CoreMsgManager.h"

#if defined(PLATFORM_ANDROID)
#define DOT1X_DEFAULT TXT("0")
#define DOT1X_EAPS_DEFAULT TXT("MD5")
#endif
#define FIND_ROUTER_MAX_ITERATIONS 30
#define FIND_ROUTER_MAX_ARPS        3
#define FIND_ROUTER_MAX_ARP_WAIT    1
#if defined(IPPCFG_BCM1108) || defined(IPPCFG_DVF99)
#define MAX_PING_WAIT   			1  // seconds
#else
#define MAX_PING_WAIT   			(1000) // milliseconds
#endif
#define NETWORK_CHECK_ONE_SEC_DELAY (1000)
#define NETWORK_LINK_CHANGE_THRESHOLD (2)
#if defined(IPPCFG_BCM1108) || defined(IPPCFG_DVF99)
#define DHCP_RETRANSMISSION_TIME	(15)
#else
#define DHCP_RETRANSMISSION_TIME    (10)
#endif

#define MAX_PING_ATTEMPTS			3

#define FILTER_RULE_NAME_ICMPDU     TXT("ICMPDU")
#define FILTER_RULE_NAME_ICMPRED    TXT("ICMPRED")

// ARP OP codes per RFC 826
#define FILTER_ARP_OP_REQUEST       1
// ICMP Types/Codes per RFC 792
#define FILTER_ICMP_ECHO_REPLY      0
#define FILTER_ICMP_UNREACH         3
 #define FILTER_ICMP_UNREACH_PORT  3  
#define FILTER_ICMP_REDIRECT        5
#define FILTER_ICMP_ECHO            8
#define FILTER_ICMP_TIME_TO_LIVE_EXCEEDED   11

//TCP FLAGS

#define FILTER_TCP_SYN_FLAG            0x02

#define FILTER_TCP_RESET_FLAG            0x04
#define FILTER_TCP_ACK_FLAG            0x10

#define RULE_TCP_SYN_FLAG          TXT("TCP SYN Flag Rate limit")
#define RULE_TCP_RST_ACK_FLAG  TXT("Drop RST ACK Flag")

#define FILTER_TRACERT_PORT_MIN     33434
#define FILTER_TRACERT_PORT_RANGE   90

#define MAX_SNMP_REQUESTS_PER_SEC 400

const unsigned long SIGNAL_MESSAGE_RATE_LIMIT = 25; //packets per second.

#define NETWORK_MODE_ETHERNET	1
#define NETWORK_MODE_WIFI 		2
// This constant is based on the default value in "/proc/sys/net/ipv6/conf/eth0/router_solicitation_delay=1"
// and is introduced to simplify the code instead of reading the value from the file
#define MAX_RTR_SOLICITATION_DELAY	1000

#define REPORT_HTTP_TRANSFER_TIMEOUT 15
#define REPORT_HTTP_CONNECTION_TIMEOUT 15
const char PHONE_REPORT_CMD[] = AVAYA_PATH_SCRIPTS "/phone-report.sh";
const CString g_sReportFileName = UTF8ToUnicode(AVAYA_PATH_SYS_LOG_FILES) + TXT("/phone_report.tar.gz");

using namespace Network;
using namespace Utils;
using namespace Msg;
using namespace Config;

//////////////////////////////////////////////////////////////////////////

#if defined (PLATFORM_VXWORKS)
void BlockHost(char *sbHostIpAddr);
void UnblockHost(char *sbHostIpAddr);
void StartUpDown(char *sbHostIpAddr, int nUpTime, int nDownTime);
void StopUpDown();
#endif

//////////////////////////////////////////////////////////////////////////
CNetworkManager::CNetworkManager()
	:m_eIPMode(Network::eMODE_NONE)
{
	m_pNetAdaptor = 0;
	m_pPacketFilter = 0;
	m_bInitialized = false;
	m_eState = eNET_UNINITIALIZED;
	m_nDhcpTimer= 0;
	m_eDhcpStatus= RC_UNKNOWN;
	m_bInterrupt= false;
	m_bTestMode=  false;
	m_bReboot= false;
	m_nReUseTimer=0;
	m_bSwitchVlan=false;
	m_bDhcpDone=true;
	m_bNetworkConfigUpdateDuringDHCP = false;
	m_bIsLinkModeUpdatedByDhcp = false;
	m_pCachedPingRequest = NULLPOINTER;
	m_bIsCraftEnabledInConflict = false;
	m_bIsCFPEnabled = false;
	m_bAreBMcastFitersEnabled = false;
#if defined(PLATFORM_ANDROID)	//SUMMIT
	m_nPortMirroring = 0;
	m_sDot1xStatus = DOT1X_DEFAULT;
	m_sDot1xEaps = DOT1X_EAPS_DEFAULT;
	m_n8021xMcastPassThruMode = 0;
	m_nNetworkMode = NETWORK_MODE_ETHERNET;
#endif
	m_eActiveNetwork = eACTIVE_NETWORK_ETHERNET;
	m_bNetworkReadySend = false ;
	m_bEthernetLinkStatas = true;
}

//////////////////////////////////////////////////////////////////////////

CNetworkManager::~CNetworkManager()
{
}

//////////////////////////////////////////////////////////////////////////

bool CNetworkManager::Initialize()
{
	CSyncAutoLock autoLock(m_Lock);

	// protect against re-init
	if (m_bInitialized)
		return true;

	// Add symbols for debug
#if defined (PLATFORM_VXWORKS)
	CPlatform::AddDebugSymbol("BlockHost", (void*)BlockHost);
	CPlatform::AddDebugSymbol("UnblockHost", (void*)UnblockHost);
	CPlatform::AddDebugSymbol("StartUpDown", (void*)StartUpDown);
	CPlatform::AddDebugSymbol("StopUpDown", (void*)StopUpDown);
#endif

	// create the Network Adaptor
	if (!m_pNetAdaptor)
	{
		if (m_bTestMode)
		{
			m_pNetAdaptor= SPARK_NEW(eMEM_MGR) CTestNetworkAdaptor();
		}
		else
		{
#if defined(PLATFORM_WINDOWS)
			m_pNetAdaptor= SPARK_NEW(eMEM_MGR) CWinNetworkAdaptor();
#elif defined(PLATFORM_VXWORKS)
			m_pNetAdaptor= SPARK_NEW(eMEM_MGR) CVxNetworkAdaptor();
#elif defined(PLATFORM_MACOSX) || defined(PLATFORM_IPHONE)
			m_pNetAdaptor = SPARK_NEW(eMEM_MGR) CMacNetworkAdaptor();
#elif defined(PLATFORM_ANDROID)
			ComputeActiveNetwork();
			m_pNetAdaptor = SPARK_NEW(eMEM_MGR) CUnixNetworkAdaptor();
#elif defined(PLATFORM_LINUX) || defined(IPPCFG_BCM1108) || defined(IPPCFG_DVF99)
#if defined(FEATURE_WIFI)
			ComputeActiveNetwork();
			if (m_eActiveNetwork == eACTIVE_NETWORK_ETHERNET)
			{
				LOGDBGHSB(CLogger::eLOG_NETMGR, "CNetworkManager::Initialize(): start Ether-Adaptor\n");
				m_pNetAdaptor = SPARK_NEW(eMEM_MGR) CUnixEthernetNetworkAdaptor();
			}
			else
			{
				LOGDBGHSB(CLogger::eLOG_NETMGR, "CNetworkManager::Initialize(): start WiFi-Adaptor\n");
				m_pNetAdaptor = SPARK_NEW(eMEM_MGR) CUnixWiFiNetworkAdaptor(this);
			}
#else
			m_pNetAdaptor = SPARK_NEW(eMEM_MGR) CUnixNetworkAdaptor();
#endif
#endif
		}
	}

	// create the Packet Filter
	if (!m_pPacketFilter)
	{
#if defined(PLATFORM_VXWORKS)
		m_pPacketFilter= &CVxPacketFilterAdaptor::Instance();
#elif defined(IPPCFG_BCM1108) || defined(IPPCFG_DVF99) || defined(PLATFORM_ANDROID)
		m_pPacketFilter = &CLinuxPacketFilterAdaptor::Instance();
#endif
	}

	if (!InitializeNetworkConfiguration())
	{
		LOGERRSB(CLogger::eLOG_NETMGR, "Failed to init Network Manager config.\n");
		return false;
	}

	// Start the Message Listener
	m_Listener.SetName(TXT("tNetworkManager"));
	m_Listener.SetObserver(static_cast<IMessageListenerObserver*> (this));

	Utils::CIntArray msgCats;
	msgCats.Add(Msg::eCT_CONFIGURATION);
	msgCats.Add(Msg::eCT_NETWORK);
	msgCats.Add(Msg::eCT_DHCP);
	msgCats.Add(Msg::eCT_REGISTRATION);
	msgCats.Add(Msg::eCT_WIFI);
	m_Listener.SetMessageCategories(msgCats);
	m_Listener.SetPriority(eTHREAD_PRIORITY_BACKGROUND);
	m_Listener.Run();

	// Start the Ethernet Link Monitor
	m_networkLinkUp.Reset();
	m_8021xLogoffSuccess.Set();

	if (IsActiveNetworkEthernet())
	{
		m_8021xAuthenticationSuccess.Reset();
		m_vlanSwitch.Reset();
		m_linkModeUpdateByDhcp.Reset();

		if (m_EthernetLinkMonitorThread.Start(TXT("tEthLinkMonitorThread"), 
				(THREADFNPTR)(EthernetLinkMonitorMethod),
				(THREADFNARG) (this),
				eTHREAD_PRIORITY_BACKGROUND, 50000) != 0)
		{
			LOGERRSB(CLogger::eLOG_NETMGR, "Cannot start EthernetLinkMonitor thread.\n");
			return false;
		}
	}

#if defined(PLATFORM_ANDROID)	//SUMMIT

	CConfigurationManager& config = CConfigurationManager::Instance();
	m_sDot1xStatus = config.GetStringParameter(eCONFIG_DOT1X_STATUS, DOT1X_DEFAULT);
	m_sDot1xEaps = config.GetStringParameter(eCONFIG_DOT1X_EAP_METHODS, DOT1X_EAPS_DEFAULT);

	if (CConfigurationManager::Instance().GetParameter(eCONFIG_PORT_MIRRORING, nParamValue) == RC_SUCCESS)
	{
		m_nPortMirroring = nParamValue;
		LOGDBGHSB(CLogger::eLOG_NETMGR, "CNetworkManager::Initialize() Set m_nPortMirroring to %d.\n",m_nPortMirroring);
		if (m_nPortMirroring == 1) //in case port_mirroing set to enable - we need to configured Marvel switch with port mirroring
		{
			LOGDBGHSB(CLogger::eLOG_NETMGR, "CNetworkManager::Initialize() enabling port mirroring.\n");
			if(m_pNetAdaptor)
			{
				if (false == m_pNetAdaptor->ConfigEthPortMirror(true))
					LOGERRSB(CLogger::eLOG_NETMGR, "CNetworkManager::Initialize() ERROR to enabled port mirroring!!!!.\n");
				else
					LOGDBGHSB(CLogger::eLOG_NETMGR, "CNetworkManager::Initialize() Success to set port mirroring from LAN port to PC port.\n");
			}
		}
	}
	else
	{
		m_nPortMirroring = 0;
		LOGERRSB(CLogger::eLOG_NETMGR, "Failed to set m_nPortMirroring=%d.\n",m_nPortMirroring);
	}
#endif
	m_bInitialized = true;
	m_eState = eNET_INITIALIZED;

	return true;
}

//////////////////////////////////////////////////////////////////////////

bool CNetworkManager::Terminate()
{
	if (IsActiveNetworkEthernet())
	{
		m_8021xLogoffSuccess.Wait();
	}
	
	CSyncAutoLock autoLock(m_Lock);

	m_networkLinkUp.Set();

	if (IsActiveNetworkEthernet())
	{
		m_8021xAuthenticationSuccess.Set();
		m_EthernetLinkMonitorThread.End();
		m_PingRequestThread.End();
#if defined(PLATFORM_ANDROID)	//SUMMIT
		m_VlanTestTimerThread.End();
#endif
	}

	m_NetworkStartupThread.End();

	m_Listener.End();

	if(m_pNetAdaptor)
	{
		SPARK_DELETE(m_pNetAdaptor, eMEM_MGR);
		m_pNetAdaptor= 0;
	}
	
#if defined(PLATFORM_VXWORKS)
	if(m_pPacketFilter)
	{
		CVxPacketFilterAdaptor::Instance().Destroy();
		m_pPacketFilter = 0;
	}
#elif defined(IPPCFG_BCM1108) || defined(IPPCFG_DVF99)
	if(m_pPacketFilter)
	{
		CLinuxPacketFilterAdaptor::Instance().Destroy();
		m_pPacketFilter = 0;
	}
#endif

	m_bInitialized = false;
	m_eState = eNET_UNINITIALIZED;
	return true;
}

//////////////////////////////////////////////////////////////////////////

bool CNetworkManager::Start()
{
	if ( !m_pNetAdaptor )
	{
		LOGERRSB(CLogger::eLOG_NETMGR, "CNetworkManager::Start() No Net Adaptor available.\n");
		return false;
	}

	if (!m_NetworkStartupThread.IsRunning() && !m_NetworkStartupThread.IsSignaledForShutdown())
	{
		if (m_NetworkStartupThread.Start(TXT("tNetworkStartupThread"), 
					(THREADFNPTR)(NetworkStartupMethod),
					(THREADFNARG) (this),
					eTHREAD_PRIORITY_BACKGROUND) != 0)
		{
			LOGERRSB(CLogger::eLOG_NETMGR, "CNetworkManager::Start() Cannot start thread.\n");
			return false;
		}
	}
	else
	{
		LOGERRSB(CLogger::eLOG_NETMGR, "CNetworkManager::Start() Thread is running.\n");
	}

#if defined (FEATURE_WIFI_EMULATION)
	LOGERRSB(CLogger::eLOG_NETMGR, "CNetworkManager::Start() STARTING Wi-Fi Test Thread\n");
	if (!m_NetworkWiFiTestThread.IsRunning() && !m_NetworkStartupThread.IsSignaledForShutdown())
	{
		if (m_NetworkWiFiTestThread.Start(TXT("tNetworkWiFiTestThread"),
				(THREADFNPTR) (NetworkWiFiTestMethod),
				(THREADFNARG) (this),
				eTHREAD_PRIORITY_BACKGROUND) != 0)
		{
			LOGERRSB(CLogger::eLOG_NETMGR, "CNetworkManager::Start() Cannot start Wi-Fi test thread.\n");
		}
	}
	else
	{
		LOGERRSB(CLogger::eLOG_NETMGR, "CNetworkManager::Start() Wi-Fi Test thread is already running.\n");
	}
#endif // FEATURE_WIFI_EMULATION

	return true;
}

//////////////////////////////////////////////////////////////////////////


THREADSIGNATURE CNetworkManager::NetworkStartupMethod(THREADFNARG arg)
{
	//CConfigurationManager::Instance().SetParameter(eCONFIG_IPV6LL_DAD_FAILED, 1);
	LOGDBGHSB(CLogger::eLOG_NETMGR, "CNetworkManager::NetworkStartupMethod().\n");

	CNetworkManager* pThis = (CNetworkManager*)arg; 
	
	pThis->m_eState = eNET_STARTING;

	CConfigurationManager& config = CConfigurationManager::Instance();

#if defined(PLATFORM_ANDROID)	//SUMMIT

	//This will be used to sync between android and CP.. Android will start DHCP once this system property is set to Done.
	char command[1024];
	int nVlanTest = 0;
	int nDhcpstd = 0;
	memset(command, '\0', sizeof(command));
	config.GetParameter(eCONFIG_VLAN_TEST_TIMER, nVlanTest);
	snprintf(command,sizeof(command),"%s %d","setprop dhcp.vlantesttimer",nVlanTest);
	LOGDBGHSB(CLogger::eLOG_NETMGR, "NetworkStartupMethod(): setprop cp.networkinit done vlantesttimer command :: %s.\n",command);
	system(command);
	memset(command, '\0', sizeof(command));
	config.GetParameter(eCONFIG_DHCP_LEASE_VIOLATION_FLAG, nDhcpstd);
	snprintf(command,sizeof(command),"%s %d","setprop dhcp.dhcpstd",nDhcpstd);
	system(command);
	LOGDBGHSB(CLogger::eLOG_NETMGR, "NetworkStartupMethod(): setprop dhcp.dhcpstd:: %s.\n",command);
	CString sCurrentIPAddress;
	if (!pThis->GetLocalIPAddress(sCurrentIPAddress))
	{
		if (config.GetBoolParameter(eCONFIG_USE_DHCP) || (pThis->m_nNetworkMode == NETWORK_MODE_WIFI))
		{
			LOGDBGHSB(CLogger::eLOG_NETMGR, "DHCP ON from Android.\n");
			// launch CP dhcp process (start monitoring files)
			LOGERRSB(CLogger::eLOG_NETMGR, "Launching DHCP Monitoring test.\n");
			// restart DHCP monitoring process
			pThis->m_eDhcpStatus = RC_INITIALIZED;
			Msg::CDhcpDiscoveryRequest requestMsg;
			CCoreMsgManager::Instance().PutMessage(&requestMsg);
			LOGDBGHSB(CLogger::eLOG_NETMGR, "Waiting for DHCP discovery results.\n"); //once network parameters will be retrieved by dhcpcd, dhcp-adaptor will get notified and configure parameters
			// update Net Mgr's internal State
			sCurrentIPAddress = (CString)TXT("0.0.0.0");
			config.SetParameter(eCONFIG_OWN_IP_ADDRESS, sCurrentIPAddress);
			pThis->m_eState = eNET_WAITING_FOR_DHCP;
			system("setprop cp.networkinit done");
			pThis->m_eState = eNET_WAITING_FOR_DHCP;
		}
		else
		{
			system("setprop cp.networkinit done");
		}
		system("setprop cp.networkinit done");
	}
	else 
	 {
	  system("setprop cp.networkinit done");
	  LOGDBGSB(CLogger::eLOG_NETMGR, "Network is already Configured send SendReadyEvent\n");
	  config.SetParameter(eCONFIG_OWN_IP_ADDRESS, sCurrentIPAddress);
	  pThis->SendReadyEvent();
	}

	if(pThis->m_pPacketFilter)
	{
		pThis->m_pPacketFilter->CacheIP(true);
        if (!pThis->m_pPacketFilter->configureIcmpRules())
        {
            LOGERRSB(CLogger::eLOG_NETMGR, "Unable to configure icmp rules\n");
        }
        if (!pThis->m_pPacketFilter->configureGARPRule())
        {
            LOGERRSB(CLogger::eLOG_NETMGR, "Unable to set garp rule\n");
        }
	}
	return (THREADRETURN) 0;
#endif

	// WIFITBD: This block can be moved as soon as WIFI service will be implemented
	// Determine SSID and credentials to connect
	if (pThis->IsActiveNetworkWiFi())
	{
		LOGDBGHSB(CLogger::eLOG_NETMGR, "CNetworkManager::NetworkStartupMethod(): WiFi INIT. blocked on m_networkLinkUp.Wait()\n");
		pThis->m_networkLinkUp.Wait();
		LOGDBGHSB(CLogger::eLOG_NETMGR, "CNetworkManager::NetworkStartupMethod(): WiFi INIT. unblocked on m_networkLinkUp.Wait()\n");
		pThis->m_networkLinkUp.Reset();
		if(!pThis->StartWiFiConnection())
		{
			LOGDBGHSB(CLogger::eLOG_NETMGR, "Wi-Fi start connection FAILED...\n");
			return (THREADRETURN)0;
		}
		else
		{
			LOGDBGHSB(CLogger::eLOG_NETMGR, "Wi-Fi start connection INITIATED...\n");
		}
	}

	// Start the Packet Filter
	if (pThis->m_pPacketFilter)
	{
		pThis->SetFilterRules();
		pThis->m_pPacketFilter->EnableFilter(true, eFILTER_RECEIVE_AND_TRANSMIT);
		pThis->m_pPacketFilter->EnableDosProtectionTCPPortsEqual();
		if (!pThis->m_bAreBMcastFitersEnabled)
		{
			pThis->m_pPacketFilter->EnableBroadcastFilter();
			pThis->m_pPacketFilter->EnableMulticastFilter();
			pThis->m_bAreBMcastFitersEnabled = true;
		}
	}

	// Wait here for network connectivity
	LOGDBGHSB(CLogger::eLOG_NETMGR, "CNetworkManager::NetworkStartupMethod(): blocked on m_networkLinkUp.Wait()\n");
	pThis->m_networkLinkUp.Wait();
	LOGDBGHSB(CLogger::eLOG_NETMGR, "CNetworkManager::NetworkStartupMethod(): de-blocked on m_networkLinkUp.Wait()\n");

	// At Present only SIP96x1 uses the DHCP process or Static IP address settings and 802.1x etc...
	// Other Platforms(Windows, Linux etc..) can fetch the IP address automatically. 
	// So, we need not do do DHCP and other initialization stuff for Windows, Linux etc... platforms
#if defined(IPPCFG_BCM1108) || defined(IPPCFG_DVF99)
	//
	// If Dot1x is enabled, DHCP and other network threads should not start until 
	// 8021x authentication is successful
	//
	int nDot1xVal = config.GetIntParameter(eCONFIG_DOT1X_STATUS);
	if ((nDot1xVal != 0) && (pThis->IsActiveNetworkEthernet()))
	{
		LOGDBGHSB(CLogger::eLOG_NETMGR, "Wait until 802.1x authentication is successful ....\n");
		pThis->m_8021xAuthenticationSuccess.Wait();
		LOGDBGHSB(CLogger::eLOG_NETMGR, "802.1x Authentication successful\n");
	}

	const CString sActiveIpAddress = pThis->GetActiveNetworkIPAddress();
	bool bIsAddressEmptyOrZero = (sActiveIpAddress == TXT("0.0.0.0")) || sActiveIpAddress.IsEmpty();
	if (pThis->IsActiveNetworkUsingDHCP() || bIsAddressEmptyOrZero)
	{
		LOGDBGHSB(CLogger::eLOG_NETMGR, "DHCP ON.\n");

		// update Net Mgr's internal State
		pThis->m_eState = eNET_WAITING_FOR_DHCP;

		// send a Network status message
		pThis->SendNetEvent(NET_MSG_DHCP_WAIT);

		pThis->m_bDhcpDone = false;

		if (pThis->IsActiveNetworkEthernet())
		{
			// Code Added to avoid Phone reboot due to VLAN Switch via DHCP SSON
			do{
				pThis->m_bSwitchVlan = false;
				pThis->DhcpVlanTest();
				if (pThis->m_bReboot)
				{
					return (THREADRETURN)0;
				}
				// The variable m_bNetworkConfigUpdateDuringDHCP is set when we receive an ConfigurationUpdate,
				// while we were doing a discovery Check, if we had an configuration update while we were in middle of
				// DHCP discovery. if there happended to be an update, then call UpdateNetworkConfiguration() to
				// validate update and do the discovery process again.
				if (pThis->m_bNetworkConfigUpdateDuringDHCP)
				{
					LOGDBGHSB(CLogger::eLOG_NETMGR, "NetworkStartupMethod(): We finished a discovery but there is some pending update.\
													So, calling UpdateNetworkConfiguration Method.\n");	
					pThis->m_Lock.Lock();
					pThis->UpdateNetworkConfiguration();
					pThis->m_Lock.Unlock();
					
				}
				pThis->m_vlanSwitch.Wait();
				pThis->m_vlanSwitch.Reset();
			}while(pThis->m_bSwitchVlan);

			// Wait for confirmation that link mode
			// update caused by DHCP was completed
			pThis->m_linkModeUpdateByDhcp.Wait();
		}

		//To allow updateNetworkConfiguration by source other than DHCP
		pThis->m_bDhcpDone = true;
		if (pThis->m_bIsCraftEnabledInConflict)
		{
			//Enable CRAFT restrictions again.
			config.SetParameter(eCONFIG_CRAFT_PROCEDURE_RESTRICTIONS, eCRAFT_RESTRICTED);
			pThis->m_bIsCraftEnabledInConflict = false;
		}

		pThis->SetActiveNetworkRouterInUse();

	}
	else //TODO duplicated code - this block is already covered in SetLocalParameters() method
	{
		LOGDBGHSB(CLogger::eLOG_NETMGR, "DHCP OFF. Proceeding with local parameters\n");
		CString sConfiguredIPAddress = pThis->GetActiveNetworkIPAddress();
		CString sConfiguredSubnetMask;
		pThis->GetActiveNetworkSubnetMask(sConfiguredSubnetMask);

		Utils::CTransportAddress configuredRouterAddress = CNetworkManager::Instance().GetActiveNetworkFirstRouterAddress();


		if (!pThis->IsValidNetworkConfig(sConfiguredIPAddress, sConfiguredSubnetMask, configuredRouterAddress.m_IPAddress.m_sAddress))
		{
			return (THREADRETURN)0;
		}
	
		// Its safe to set the Network interface with the locally configured IP address
		if (!pThis->m_pNetAdaptor->SetLocalIPAddress(sConfiguredIPAddress, sConfiguredSubnetMask))
		{
			LOGERRSB(CLogger::eLOG_NETMGR, "Unable to set the net interface with the local IP address "_LS_".\n", (LPCXSTR)sConfiguredIPAddress);
			return (THREADRETURN)0;
		}

		if (!pThis->m_NetworkStartupThread.IsSignaledForShutdown())
		{
			pThis->FindRouter();
		}
	}
    
#endif

#if (defined (PLATFORM_WINDOWS) || defined (WIN32))

	if (pThis->m_bTestMode)
	{
		CString sConfiguredIPAddress = pThis->GetActiveNetworkIPAddress();
		CString sConfiguredSubnetMask;
		pThis->GetActiveNetworkSubnetMask(sConfiguredSubnetMask);
		Utils::CTransportAddress configuredRouterAddress= config.GetFirstServerAddress(eCONFIG_DEFAULT_GATEWAY_ADDRESS_LIST);

		if (pThis->IsValidNetworkConfig(sConfiguredIPAddress, sConfiguredSubnetMask, configuredRouterAddress.m_IPAddress.m_sAddress) == false)
		{
			return false;
		}
	}
#endif
	// update Net Mgr's internal State
	pThis->m_eState = eNET_READY;

	CString sIp;
#if !(defined (PLATFORM_WINDOWS) || defined (WIN32))
	pThis->GetLocalIPAddress (sIp);
#else
	// QT Emulator will reuse config.xml address assigned  before the restart
	// This address can changed when the emergency connection is established or 
	// the registration socket is connected to SM, based on the socket SASA bestIP selection for a destination SM IP
	// NOTE: Both emergency socket and registration socket use the same SIP Controller List. 
	// Registration can reuse the emergency socket and SASA address can be stored once in Config Mgr and config.xml
	if (config.GetParameter(Config::eCONFIG_OWN_IP_ADDRESS, sIp) != RC_SUCCESS)
	{
		return false;
	}
#endif
	
#if !(defined(IPPCFG_BCM1108) || defined(IPPCFG_DVF99) || defined(PLATFORM_ANDROID)) // as it isn't needed in Android Summit- already done by NetworkMonitor
#if !(defined (PLATFORM_WINDOWS) || defined (WIN32))
	if(config.SetParameter(eCONFIG_OWN_IP_ADDRESS, sIp) != RC_SUCCESS)
	{
		LOGERRSB(CLogger::eLOG_NETMGR, "Unable to set IP address to eCONFIG_OWN_IP_ADDRESS\n");
	}
#endif
#endif

#if defined(IPPCFG_BCM1108) || defined(IPPCFG_DVF99)
	pThis->CheckDNS();
#endif

	if(pThis->m_pPacketFilter)
	{
		pThis->m_pPacketFilter->CacheIP(true);
       #if defined(PLATFORM_ANDROID)
        if (!pThis->m_pPacketFilter->configureIcmpRules())
        {
            LOGERRSB(CLogger::eLOG_NETMGR, "Unable to configure icmp rules\n");
        }
       #endif
    
	}

#if defined(IPPCFG_BCM1108) || defined(IPPCFG_DVF99)
	// If LAN port mode was updated by DHCP wait for connectivity
	// before sending the READY event. It is necessary to ensure
	// that other modules don't fail in attempt to use network
	// right after receving the event.
	if (pThis->m_bIsLinkModeUpdatedByDhcp)
	{
		for (;;)
		{
			if (!pThis->m_NetworkStartupThread.IsSignaledForShutdown())
			{
				CPlatform::DelayThread(NETWORK_CHECK_ONE_SEC_DELAY);
			}
			else
			{
				return (THREADRETURN)0;
			}
			etEthLinkMode eCurrentLanLinkStatus  = eETH_LINK_MODE_INVALID;
			pThis->m_pNetAdaptor->GetEtherLinkStatus(eETH_PORT_LAN, eCurrentLanLinkStatus);
			if (eCurrentLanLinkStatus != eETH_LINK_MODE_DISABLED)
			{
				break;
			}
		}
	}
#endif

	if (config.GetIntParameter(eCONFIG_IPV6_STAT) == 1)
	{
		if (pThis->LoadIPv6Module())
		{
			// The default mode: SLAAC should be disabled
			pThis->m_pNetAdaptor->EnableSLAAC(false);
			int nDadNsTransmits = config.GetIntParameter(eCONFIG_IPV6DADXMITS);
			if (pThis->m_pNetAdaptor->SetDAD(nDadNsTransmits))
			{
				pThis->m_pNetAdaptor->EnableIPv6();
				// Duplicate Address Detection for Link Local address supported when the value of IPV6DADXMITS is not "0", 
				// otherwise continue boot the phone
				if (nDadNsTransmits > 0)
				{
					// Wait until DAD ended typically 2sec and maximum 6sec.
					// The wait time is: (MAX_RTR_SOLICITATION_DELAY=1sec) + (DupAddrDetectTransmits=IPV6DADXMITS) * RetransTimer),
					// where Retrans Timer=1 sec during DAD and omitted to simplify the code
					CPlatform::DelayThread(MAX_RTR_SOLICITATION_DELAY + nDadNsTransmits*1000);
					// If DAD failed phone automatically disables IPv6 stack
					if (pThis->m_pNetAdaptor->GetSystemDisableIPv6Flag() == 1)
					{
						// Manually disable IPv6 stack again for updating IPv6 module status
						pThis->m_pNetAdaptor->EnableIPv6(false);
						// Need to send error log message with MAC address and to notify UI about IPv6LL address conflict
						CString sMACAddress;
						pThis->m_pNetAdaptor->GetHardwareAddress(sMACAddress);
						pThis->SendNetEvent(NET_MSG_IPV6LL_ADDRESS_CONFLICT, sMACAddress);
						LOGERRSB(CLogger::eLOG_NETMGR, "ERROR: IPv6LL Address conflict: MAC addr = "_LS_"\n", (LPCXSTR)sMACAddress);
						// Exit without sending Network Ready Event, it means that phone interrupts boot and stays on Startup screen
						return (THREADRETURN)0;
					}
				}

				CString sIPv6LLAddress;
				if (pThis->m_pNetAdaptor->GetLinkLocalIPv6Address(sIPv6LLAddress))
				{
					config.SetParameter(eCONFIG_OWN_IPV6_LL_ADDRESS, sIPv6LLAddress);
				}
				else
				{
					LOGERRSB(CLogger::eLOG_NETMGR, "Unable to get IPv6 Link-Local address\n");				
				}
			}
			else
			{
				LOGERRSB(CLogger::eLOG_NETMGR, "ERROR: cannot configure DAD for IPv6LL address\n");
			}
			// TODO: assign global IPv6 address to interface using work of SIP96X1-17256 and SIP96X1-15285 , DAD starts automatically
			CString sGlobalIPv6Address = config.GetStringParameter(eCONFIG_OWN_IPV6_ADDRESS);
			
			if (nDadNsTransmits > 0)
			{
				// Wait until DAD ended typically 2sec and maximum 6sec.
				// The wait time is: (MAX_RTR_SOLICITATION_DELAY=1sec) + (DupAddrDetectTransmits=IPV6DADXMITS) * RetransTimer),
				// where Retrans Timer=1 sec during DAD and omitted to simplify the code
				CPlatform::DelayThread(MAX_RTR_SOLICITATION_DELAY + nDadNsTransmits*1000);
				if (pThis->m_pNetAdaptor->IsIPv6AddressTentative(sGlobalIPv6Address))
				{
					pThis->SendNetEvent(NET_MSG_IPV6_ADDRESS_CONFLICT, sGlobalIPv6Address);
					LOGERRSB(CLogger::eLOG_NETMGR, "ERROR: IPv6 Address conflict: "_LS_"\n", (LPCXSTR)sGlobalIPv6Address);
					// Exit without sending Network Ready Event, it means that phone interrupts boot and stays on Startup screen
					return (THREADRETURN)0;
				}
			}
		}
	}

	// Check the connectivity
	CString sRouter = config.GetStringParameter(eCONFIG_ROUTER_IN_USE);
	for (int i = 0; i < 3; i++)
	{
		CPlatform::DelayThread(2); // wait for 2 milisecond
		if (pThis->PingRemoteHost(sRouter)) // default ping wait time is 1 sec.
		{
			break;
		}
	}
	// network is up, send network ready event
	pThis->SendNetEvent(NET_MSG_READY, sIp);

	return (THREADRETURN)0;
}

//////////////////////////////////////////////////////////////////////////

THREADSIGNATURE CNetworkManager::EthernetLinkMonitorMethod(THREADFNARG arg)
{
	CNetworkManager* pThis= (CNetworkManager*)arg;
	CConfigurationManager& config= CConfigurationManager::Instance();

	unsigned long ulLanChangeSecs = 0;
	unsigned long ulPcChangeSecs  = 0;
	etEthLinkMode eCurrentLanLinkStatus  = eETH_LINK_MODE_DISABLED;
	etEthLinkMode eCurrentPcLinkStatus   = eETH_LINK_MODE_DISABLED;
	etEthLinkMode ePreviousLanLinkStatus = eETH_LINK_MODE_INVALID;
	etEthLinkMode ePreviousPcLinkStatus  = eETH_LINK_MODE_INVALID;

	// Send an initial Ethernet Link status Event for both ports
	pThis->m_pNetAdaptor->GetEtherLinkStatus(eETH_PORT_LAN, eCurrentLanLinkStatus);
	pThis->m_pNetAdaptor->GetEtherLinkStatus(eETH_PORT_PC,  eCurrentPcLinkStatus);
	pThis->SendEthernetStatusMsg(eETH_PORT_LAN, eCurrentLanLinkStatus);
	pThis->SendEthernetStatusMsg(eETH_PORT_PC, eCurrentPcLinkStatus);

	// Update the status config parameter
	if (eCurrentLanLinkStatus == eETH_LINK_MODE_DISABLED)
	{
		config.SetParameter(eCONFIG_ETHERNET1_INTERFACE_CURRENT_OPERATIONAL_MODE, 1);
	}
	else
	{
		config.SetParameter(eCONFIG_ETHERNET1_INTERFACE_CURRENT_OPERATIONAL_MODE, (int)eCurrentLanLinkStatus);
	}
	if (eCurrentPcLinkStatus == eETH_LINK_MODE_DISABLED)
	{
		config.SetParameter(eCONFIG_ETHERNET2_INTERFACE_CURRENT_OPERATIONAL_MODE, 1);
	}
	else
	{
		config.SetParameter(eCONFIG_ETHERNET2_INTERFACE_CURRENT_OPERATIONAL_MODE, (int)eCurrentPcLinkStatus);
	}

	ePreviousLanLinkStatus = eCurrentLanLinkStatus;
	ePreviousPcLinkStatus  = eCurrentPcLinkStatus;

	// Monitor the LAN and PC Ethernet Links
	while (!pThis->m_EthernetLinkMonitorThread.IsSignaledForShutdown())
	{
#if defined(PLATFORM_ANDROID)
	   if (pThis->m_nNetworkMode == NETWORK_MODE_ETHERNET)
	     {
#endif
		// LAN port
		if(pThis->m_pNetAdaptor->GetEtherLinkStatus(eETH_PORT_LAN, eCurrentLanLinkStatus))
		{
			if (eCurrentLanLinkStatus != ePreviousLanLinkStatus)
			{
				ulLanChangeSecs++;

				// Acknowledge the change if it persists for at least NETWORK_LINK_CHANGE_THRESHOLD seconds
				if (ulLanChangeSecs >= NETWORK_LINK_CHANGE_THRESHOLD) 
				{
					// Update the status config parameter
					if (eCurrentLanLinkStatus == eETH_LINK_MODE_DISABLED)
					{
#if defined(PLATFORM_ANDROID)
					 	if(pThis->m_pNetAdaptor->GetEtherSwitchStatus())
	 					{
						  config.SetParameter(eCONFIG_ETHERNET1_INTERFACE_CURRENT_OPERATIONAL_MODE, 1);
						}
						else
	 					{
					            LOGERRSB(CLogger::eLOG_NETMGR, "Ethernet Switch is not responding\n");
						    //Stop the dhcp service
						    system("setprop ctl.start mss");
						    CPlatform::DelayThread(500);
						    abort();	
	 					}
#else
						  config.SetParameter(eCONFIG_ETHERNET1_INTERFACE_CURRENT_OPERATIONAL_MODE, 1);
#endif
					}
					else
					{
						config.SetParameter(eCONFIG_ETHERNET1_INTERFACE_CURRENT_OPERATIONAL_MODE, (int)eCurrentLanLinkStatus);
					}

					LOGDBGHSB(CLogger::eLOG_NETMGR, "Primary Ethernet link status changed from <%d> to <%d>\n", ePreviousLanLinkStatus, eCurrentLanLinkStatus);

					// Send event identifying link change
					pThis->SendEthernetStatusMsg(eETH_PORT_LAN, eCurrentLanLinkStatus);

					ePreviousLanLinkStatus = eCurrentLanLinkStatus;
					ulLanChangeSecs = 0;
				}
			}
			else
			{
				ulLanChangeSecs = 0;
			}
		}

		// PC port
		if (pThis->m_pNetAdaptor->GetEtherLinkStatus(eETH_PORT_PC,  eCurrentPcLinkStatus))
		{
			if (eCurrentPcLinkStatus != ePreviousPcLinkStatus)
			{
				ulPcChangeSecs++;

				// Acknowledge the change if it persists for at least NETWORK_LINK_CHANGE_THRESHOLD seconds
				if (ulPcChangeSecs >= NETWORK_LINK_CHANGE_THRESHOLD) 
				{
					// Update the status config parameter
					if (eCurrentPcLinkStatus == eETH_LINK_MODE_DISABLED)
					{
						config.SetParameter(eCONFIG_ETHERNET2_INTERFACE_CURRENT_OPERATIONAL_MODE, 1);
					}
					else
					{
						config.SetParameter(eCONFIG_ETHERNET2_INTERFACE_CURRENT_OPERATIONAL_MODE, (int)eCurrentPcLinkStatus);
					}

					LOGDBGHSB(CLogger::eLOG_NETMGR, "Secondary Ethernet link status changed from <%d> to <%d>\n", ePreviousPcLinkStatus, eCurrentPcLinkStatus);

					// Send event identifying link change
					pThis->SendEthernetStatusMsg(eETH_PORT_PC, eCurrentPcLinkStatus);

					ePreviousPcLinkStatus = eCurrentPcLinkStatus;
					ulPcChangeSecs = 0;
#ifdef PLATFORM_ANDROID
                    /* 0 - passthrough enabled without Proxy Logoff, 1- enabled with proxy logoff, 2- pass through disabled*/
                    if (( 1 == pThis->m_n8021xMcastPassThruMode) && (eCurrentPcLinkStatus == eETH_LINK_MODE_DISABLED))
                    {
                        if (false == pThis->m_pNetAdaptor->SendProxyLogoff())
                            LOGERRSB(CLogger::eLOG_NETMGR, "SendProxyLogoff ERROR in sending for PC Port!!!!.\n");
                        else
                            LOGDBGHSB(CLogger::eLOG_NETMGR, "SendProxyLogoff Successfully sent\n");
                    }
#endif

				}

			}
			else
			{
				ulPcChangeSecs = 0;
			}
		}
#if defined(PLATFORM_ANDROID)
	 }
#endif
		// chill out for a second
		if (!pThis->m_EthernetLinkMonitorThread.IsSignaledForShutdown())
		{
			CPlatform::DelayThread(NETWORK_CHECK_ONE_SEC_DELAY);
		}
	}
	return (THREADRETURN) 0;
}

//////////////////////////////////////////////////////////////////////////

void CNetworkManager::Restart(bool bWaitUntilIdle)
{
	if (!m_bInterrupt)
	{
		m_bReboot= true; 
		Msg::CShutdownRequest request;
		request.m_bWaitUntilIdle = bWaitUntilIdle;
		LOGDBGHSB(CLogger::eLOG_NETMGR, "Reboot phone.\n");
		CCoreMsgManager::Instance().PutMessage(&request);
	}
}

//////////////////////////////////////////////////////////////////////////

bool CNetworkManager::SetLocalParameters(THREADFNARG arg)
{
	CNetworkManager* pThis = (CNetworkManager*)arg;
	CConfigurationManager& config = CConfigurationManager::Instance();
	LOGDBGHSB(CLogger::eLOG_NETMGR, "DHCP OFF. Proceeding with local parameters\n");
	CString sConfiguredIPAddress = pThis->GetActiveNetworkIPAddress();
	CString sConfiguredSubnetMask;
	pThis->GetActiveNetworkSubnetMask(sConfiguredSubnetMask);
	
	LOGERRSB(CLogger::eLOG_NETMGR, "_ido_ sConfiguredIPAddress="_LS_", sConfiguredSubnetMask="_LS_".\n", (LPCXSTR)sConfiguredIPAddress, (LPCXSTR)sConfiguredSubnetMask);

	Utils::CTransportAddress configuredRouterAddress = GetActiveNetworkFirstRouterAddress();
	if (pThis->IsValidNetworkConfig(sConfiguredIPAddress, sConfiguredSubnetMask, configuredRouterAddress.m_IPAddress.m_sAddress) == false)
	{
		LOGDBGHSB(CLogger::eLOG_NETMGR, "Error. Invalid Network configurations.\n");
		return false;
	}
	// Its safe to set the Network interface with the locally configured IP address
	if (pThis->m_pNetAdaptor->SetLocalIPAddress(sConfiguredIPAddress, sConfiguredSubnetMask) == false)
	{
		LOGERRSB(CLogger::eLOG_NETMGR, "Unable to set the net interface with the local IP address "_LS_".\n", (LPCXSTR)sConfiguredIPAddress);
		return false;
	}
	if (!pThis->m_NetworkStartupThread.IsSignaledForShutdown())
	{
		pThis->FindRouter();
	}
	return true;
}

//////////////////////////////////////////////////////////////////////////

bool CNetworkManager::ComputeWiFiNetworkSsid(Utils::CString& sSsId, CWifiCredentials& credentials)
{
	CConfigurationManager& config = CConfigurationManager::Instance();
	CString sWlanEssid;

	/*
	 *  If WLAN_ESSID is NOT empty (i.e., was received the last time we read 46xxsettings.txt)
	 *  reset value WLANACTIVESSID = WLAN_ESSID.
	 *  Otherwise, send event indicating that there is no SSID for connect
	 */
	sWlanEssid = config.GetStringParameter(eCONFIG_WLAN_ESSID);
	if (!sWlanEssid.IsEmpty())
	{
		sSsId = sWlanEssid;
		config.SetParameter(eCONFIG_WLAN_ACTIVE_SSID, sSsId);
	}
	else
	{
		LOGDBGHSB(CLogger::eLOG_NETMGR, "CNetworkManager::ComputeWiFiNetworkSsid(): Network Mode: Wi-Fi - cannot determine SSID.\n");
		SendNetEvent(NET_MSG_WIFI_NO_SSID);
		return false;
	}

	/*
	 *  Search sSsId (==WLANACTIVESSID) in the WLANLIST 
	 *  (WLANLIST must be returned from wlanlist.xml)>
	 *  and extract credentials for the specified sSsId
	 *  Otherwise, send event indicating Authentication is failed
	 */
	if (!ExtractCredentialsForSSID(sSsId, credentials))
	{
		LOGDBGHSB(CLogger::eLOG_NETMGR, "CNetworkManager::ComputeWiFiNetworkSsid(): Network Mode: Wi-Fi - no credentials for SSID.\n");
		SendNetEvent(NET_MSG_WIFI_STATUS_AUTH_FAILED);
		return false;
	}
	LOGDBGHSB(CLogger::eLOG_NETMGR, "CNetworkManager::ComputeWiFiNetworkSsid(): Set Wi-Fi SSID = %ls\n", (LPCXSTR)(sSsId));
	return true;
}

//////////////////////////////////////////////////////////////////////////

bool CNetworkManager::ExtractCredentialsForSSID(const Utils::CString& sSsId, CWifiCredentials& credentials)
{
	/* WIFITBD: Searching WLANACTIVESSID in WLANLIST (WLANLIST must be returned from wlanlist.xml) 
	if(WLANACTIVESSID==WLANLIST[i].SSID) - extract credentials from WLANLIST[i] to the "credentials"
	else - return false
	*/
	return true; // for emulation only
}

//////////////////////////////////////////////////////////////////////////

bool CNetworkManager::StartWiFiConnection()
{
	CString sSSID;
	CWifiCredentials credentials;
	if (ComputeWiFiNetworkSsid(sSSID, credentials))
	{
		if (m_pNetAdaptor != NULL)
		{
			eReturnCode res = m_pNetAdaptor->ConnectNetwork(sSSID, credentials);
			// WIFITBD: Inform WiFiModel: start connection to the SSID-network with result "res"
			// "res" indicates result of the request BP (RC_SUCCESS or any other)
			// if res == RC_SUCCESS should start getting async WIFI_EVENT_CONNECTION_STATUS events
			// Otherwise - WiFiModel should make a decision about next steps
			if(res != RC_SUCCESS)
			{
				LOGDBGHSB(CLogger::eLOG_NETMGR, "CNetworkManager::StartWiFiConnection(): FAILED SSID = %ls, res = %d\n", (LPCXSTR)(sSSID), res);
				return false;
			}
		}
	}
	LOGDBGHSB(CLogger::eLOG_NETMGR, "CNetworkManager::StartWiFiConnection(): started SSID = %ls\n", (LPCXSTR)(sSSID));
	return true;
}

//////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////

etVlanAction CNetworkManager::CheckNewL2Qos()
{
	if (IsActiveNetworkWiFi())
	{
		LOGDBGSB(CLogger::eLOG_NETMGR, "CheckNewL2Qos: Wi-Fi mode. Exit.\n");
		return eNO_ACTION;
	}

	if(m_pNetAdaptor != NULL)
	{
		return m_pNetAdaptor->CheckNewL2Qos();
	}
	return eNO_ACTION;
}

//////////////////////////////////////////////////////////////////////////

bool CNetworkManager::CheckL2QosTagging()
{
	if (m_pNetAdaptor != NULL)
	{
		return m_pNetAdaptor->CheckL2QosTagging();
	}
	return false;
}

//////////////////////////////////////////////////////////////////////////

bool CNetworkManager::CheckLinks()
{
	CConfigurationManager& config= CConfigurationManager::Instance();
	etEthLinkMode eCurrentLinkMode;
	int nConfiguredLinkMode;
	bool bReturnVal= true;
	bool bCurrentLinkAutoMDIX = false;
	bool bConfiguredLinkAutoMDIX = false;

	if (IsActiveNetworkEthernet())
	{
		if(config.GetParameter(eCONFIG_ETHERNET1_INTERFACE_STATUS, nConfiguredLinkMode) != RC_SUCCESS)
		{
			LOGERRSB(CLogger::eLOG_NETMGR, " Unable to get config LAN Ethernet link mode.\n");
			return false;
		}

		if(!m_pNetAdaptor->GetEtherLinkMode(eETH_PORT_LAN, eCurrentLinkMode))
		{
			LOGERRSB(CLogger::eLOG_NETMGR, " Unable to get current LAN Ethernet link mode.\n");
			return false;
		}

		if(eCurrentLinkMode != (etEthLinkMode)nConfiguredLinkMode || nConfiguredLinkMode == eETH_LINK_MODE_DISABLED)
		{
			if(!m_pNetAdaptor->SetEtherLinkMode(eETH_PORT_LAN, (etEthLinkMode)nConfiguredLinkMode))
			{
				LOGERRSB(CLogger::eLOG_NETMGR, "Unable to set current LAN Ethernet link mode %d\n", 
					nConfiguredLinkMode);
				bReturnVal=false;
			}
#if defined(IPPCFG_BCM1108) || defined(IPPCFG_DVF99)
			else
			{
				// If LAN port mode was changed by
				// DHCP notify the startup thread
				if (!m_bDhcpDone)
				{
					m_bIsLinkModeUpdatedByDhcp = true;
				}
			}
#endif
		}

		if(config.GetParameter(eCONFIG_ETHERNET2_INTERFACE_STATUS, nConfiguredLinkMode) != RC_SUCCESS)
		{
			LOGERRSB(CLogger::eLOG_NETMGR, " Unable to get config PC Ethernet link mode.\n");
			return false;
		}

		if(!m_pNetAdaptor->GetEtherLinkMode(eETH_PORT_PC, eCurrentLinkMode))
		{
			LOGERRSB(CLogger::eLOG_NETMGR, " Unable to get current PC Ethernet link mode.\n");
			return false;
		}
		// If the telephone disables the secondary Ethernet interface (PHY2) while a link is active
		if ((etEthLinkMode)nConfiguredLinkMode == eETH_LINK_MODE_DISABLED)
		{
			if ((eCurrentLinkMode != eETH_LINK_MODE_DISABLED) && (eCurrentLinkMode != eETH_LINK_MODE_INVALID))
			{
				LOGWRNSB(CLogger::eLOG_NETMGR, CLogger::eLOG_MESSAGE_FORMAT_1, ".TEL PHY2-401 Secondary Ethernet interface disabled");
			}
		}

		if(eCurrentLinkMode != (etEthLinkMode)nConfiguredLinkMode || nConfiguredLinkMode == eETH_LINK_MODE_DISABLED )
		{
			if(nConfiguredLinkMode != eETH_LINK_MODE_DISABLED)
			{
				m_pNetAdaptor->SetEtherLinkStatus(eETH_PORT_PC,true);
			}
			if(!m_pNetAdaptor->SetEtherLinkMode(eETH_PORT_PC, (etEthLinkMode)nConfiguredLinkMode))
			{
				LOGERRSB(CLogger::eLOG_NETMGR, "Unable to set current PC Ethernet link mode %d\n", 
					nConfiguredLinkMode);
				bReturnVal=false;
			}
		}

		//configure MDIX:starting //
		if(config.GetParameter(eCONFIG_ETHERNET2_AUTO_MDIX_ENABLED, bConfiguredLinkAutoMDIX) != RC_SUCCESS)
		{
			LOGERRSB(CLogger::eLOG_NETMGR, " Unable to get config PC Ethernet link Auto MDIX.\n");
			LOGERRSB(CLogger::eLOG_NETMGR, " then set bConfiguredLinkAutoMDIX to true.\n");
			bConfiguredLinkAutoMDIX = true; //set to default value.
		}
		else
		{
			LOGDBG(CLogger::eLOG_NETMGR, TXT("DATA MANAGER:PC Ethernet link Auto MDIX set to %s.\n"), (bConfiguredLinkAutoMDIX ? TXT("enabled") : TXT("disabled")));
		}

		if(!GetEtherLinkAutoMDIX(eETH_PORT_PC, bCurrentLinkAutoMDIX))
		{
			LOGERRSB(CLogger::eLOG_NETMGR, " Unable to get current PC Ethernet link Auto MDIX setting.\n");
			LOGERRSB(CLogger::eLOG_NETMGR, " then set bCurrentLinkAutoMDIX to !(bCurrentLinkAutoMDIX).\n");
			bCurrentLinkAutoMDIX = !(bCurrentLinkAutoMDIX);
		}
		else
		{
			LOGDBGSB(CLogger::eLOG_NETMGR, "MARVELL SWITCH:PC Ethernet link Auto MDIX is %s.\n", (bCurrentLinkAutoMDIX ? "enabled" : "disabled"));
		}

		// Update the Auto MDIX value only if the value has changed 
		if (bConfiguredLinkAutoMDIX != bCurrentLinkAutoMDIX)
		{
			LOGDBGSB(CLogger::eLOG_NETMGR, "%s PC Ethernet link Auto MDIX.\n", (bConfiguredLinkAutoMDIX ? "Enabling" : "Disabling"));
			if(!SetEtherLinkAutoMDIX(eETH_PORT_PC, bConfiguredLinkAutoMDIX))
			{
				LOGERRSB(CLogger::eLOG_NETMGR, "Unable to %s PC Ethernet link Auto MDIX\n",
					(bConfiguredLinkAutoMDIX ? "enable" : "disable"));
				bReturnVal=false;
			}
		}
		//configure MDIX:end //
#if defined(IPPCFG_BCM1108) || defined(IPPCFG_DVF99)
		// Make sue we have set the NVRAM directory updated with the correct value
		// The file /nvdata/etc/pcport_automdix_disable will be created if auto MDIX
		// is being disabled
		// As the file might be erased by anyone with access to the file system,
		// the file presence will be checked even if no change to the settings is 
		// detected
		DIR *dptr;
		if ((dptr = (opendir (AVAYA_PATH_NVDATA"/etc"))) == NULL)
		{
			LOGDBGSB(CLogger::eLOG_NETMGR, "etc folder does not exist. Creating new folder\n");
			system ("mkdir "AVAYA_PATH_NVDATA"/etc");
		}
		else
		{
			closedir (dptr);
		}

		FILE* AutoMdixFile = fopen (PCPORT_AUTOMDIX_FILE_FULLPATH, "r");
		if (AutoMdixFile != NULL)
		{
			fclose(AutoMdixFile);
			AutoMdixFile = NULL;
			if (bConfiguredLinkAutoMDIX)
			{
				LOGDBGSB(CLogger::eLOG_NETMGR, "Removing pcport_automdix_disable file\n");
				system ("rm "PCPORT_AUTOMDIX_FILE_FULLPATH);
			}
		}
		else
		{
			if (!bConfiguredLinkAutoMDIX)
			{
				LOGDBGSB(CLogger::eLOG_NETMGR, "Creating pcport_automdix_disable file\n");
				system ("echo \" \" > "PCPORT_AUTOMDIX_FILE_FULLPATH);
			}
		}
#endif
	}
	else
	{
#if defined(FEATURE_WIFI)
		//PC Port disabled as current Network mode is Wi-Fi (not Android)
		m_pNetAdaptor->SetEtherLinkStatus(eETH_PORT_PC,false);
#endif
		LOGDBGSB(CLogger::eLOG_NETMGR, "CheckLinks : Network Mode = Wi-Fi\n");
	}
	return bReturnVal;
}

//////////////////////////////////////////////////////////////////////////

bool CNetworkManager::CheckDNS()
{
	CConfigurationManager& config= CConfigurationManager::Instance();
	CStringArray sDnsServerAddresses;
	CString sDomainName;
	CString sDnsServerInUse;
	bool bReturnVal = true;

	// Get the configured DNS parameters
	if(config.GetParameter(eCONFIG_DNS_SERVER_LIST, sDnsServerAddresses) != RC_SUCCESS)
	{
		LOGERRSB(CLogger::eLOG_NETMGR, "Unable to get DNS Server list from Config Mgr.\n");
		return false;
	}  
	if(config.GetParameter(eCONFIG_DNS_DOMAIN, sDomainName) != RC_SUCCESS)
	{
		LOGERRSB(CLogger::eLOG_NETMGR, "Unable to get domain name from Config Mgr.\n");
		return false;
	}

	// Set the adaptor DNS parameters
	if(!m_pNetAdaptor->SetDnsServers(sDnsServerAddresses))
	{
		LOGERRSB(CLogger::eLOG_NETMGR, "Unable to update the DNS server addresses.\n");
		config.RestoreDefaultParameterValue(eCONFIG_DNS_SERVER_IN_USE); 
		bReturnVal = false;
	}
	if(!m_pNetAdaptor->SetDomainName(sDomainName))
	{
		LOGERRSB(CLogger::eLOG_NETMGR, "Unable to update the DNS Domain name.\n");
		bReturnVal = false;
	}

	// Update the DNS sever in use
	if(!m_pNetAdaptor->GetCurrentDnsServer(sDnsServerInUse))
	{
		LOGERRSB(CLogger::eLOG_NETMGR, "Unable to get the DNS server address in use.\n");
		bReturnVal = false;
	}
	else if(config.SetParameter(eCONFIG_DNS_SERVER_IN_USE, sDnsServerInUse) != RC_SUCCESS)
	{
		LOGERRSB(CLogger::eLOG_NETMGR, "Unable to set DNS Server in use to Config Mgr.\n");
		bReturnVal = false;
	}  

	return bReturnVal;
}

//////////////////////////////////////////////////////////////////////////

bool CNetworkManager::SetFilterRules()
{
#if defined(PLATFORM_ANDROID)
    // Summit implements its own packet filtering based on these rules
    // (see kernel_imx/drivers/avaya/kernel_module/nf_avaya_packet_filtering.c)
    // The packet filtering rules in the case of 96x1 gets applied during initilization here
    // In the case of summit it gets applied during platform initialization 
    // from nf_avaya_packet_filtering_open
    return true;
#endif
	if ( !m_pPacketFilter )
	{
		return false;
	}

	// Create rules
	CFilterRule rule;
	rule.m_sName = TXT("ARP Rx Rate Limit");
	rule.m_eAction = eFILTER_RATE_LIMIT;
	rule.m_eDirection = eFILTER_RECEIVE;
	rule.m_protocol.eProto = eFILTER_ARP;
	rule.m_protocol.nSubTypeArrays[FILTER_ARP_OP_INDEX].Add(FILTER_ARP_OP_REQUEST);
	rule.m_rate.ulPacketsPerSecond = 2;
	rule.m_rate.ulMaxHosts = 10;
	if (!m_pPacketFilter->AddRule(rule))
		LOGERRSB(CLogger::eLOG_NETMGR, "Unable to add "_LS_" Rule.\n", (LPCXSTR)rule.m_sName);

	rule.Reset();
	rule.m_sName = TXT("ARP Tx Rate Limit");
	rule.m_eAction = eFILTER_RATE_LIMIT;
	rule.m_eDirection = eFILTER_TRANSMIT;
	rule.m_protocol.eProto = eFILTER_ARP;
	rule.m_protocol.nSubTypeArrays[FILTER_ARP_OP_INDEX	].Add(FILTER_ARP_OP_REQUEST);
	rule.m_rate.ulPacketsPerSecond = 1;
	rule.m_rate.ulMaxHosts = 0;
	if (!m_pPacketFilter->AddRule(rule))
		LOGERRSB(CLogger::eLOG_NETMGR, "Unable to add "_LS_" Rule.\n", (LPCXSTR)rule.m_sName);

	rule.Reset();
	rule.m_sName = TXT("ICMP Drop All");
	rule.m_eAction = eFILTER_DROP;
	rule.m_eDirection = eFILTER_RECEIVE_AND_TRANSMIT;
	rule.m_protocol.eProto = eFILTER_ICMP;
	if (!m_pPacketFilter->AddRule(rule))
		LOGERRSB(CLogger::eLOG_NETMGR, "Unable to add "_LS_" Rule.\n", (LPCXSTR)rule.m_sName);

	rule.Reset();
	rule.m_sName = TXT("ICMP Accept Rx");
	rule.m_eAction = eFILTER_ACCEPT;
	rule.m_eDirection = eFILTER_RECEIVE;
	rule.m_protocol.eProto = eFILTER_ICMP;
	rule.m_protocol.nSubTypeArrays[FILTER_ICMP_TYPE_INDEX].Add(FILTER_ICMP_ECHO_REPLY);
	rule.m_protocol.nSubTypeArrays[FILTER_ICMP_TYPE_INDEX].Add(FILTER_ICMP_UNREACH);
	rule.m_protocol.nSubTypeArrays[FILTER_ICMP_TYPE_INDEX].Add(FILTER_ICMP_ECHO);
	rule.m_protocol.nSubTypeArrays[FILTER_ICMP_TYPE_INDEX].Add(FILTER_ICMP_TIME_TO_LIVE_EXCEEDED);
	if (!m_pPacketFilter->AddRule(rule))
	{
		LOGERRSB(CLogger::eLOG_NETMGR, "Unable to add "_LS_" Rule.\n", (LPCXSTR)rule.m_sName);
	}

	rule.Reset();
	rule.m_sName = TXT("ICMP Accept Tx");
	rule.m_eAction = eFILTER_ACCEPT;
	rule.m_eDirection = eFILTER_TRANSMIT;
	rule.m_protocol.eProto = eFILTER_ICMP;
	rule.m_protocol.nSubTypeArrays[FILTER_ICMP_TYPE_INDEX].Add(FILTER_ICMP_ECHO_REPLY);
	rule.m_protocol.nSubTypeArrays[FILTER_ICMP_TYPE_INDEX].Add(FILTER_ICMP_ECHO);
	if (!m_pPacketFilter->AddRule(rule))
		LOGERRSB(CLogger::eLOG_NETMGR, "Unable to add "_LS_" Rule.\n", (LPCXSTR)rule.m_sName);

	rule.Reset();
	rule.m_sName = TXT("ICMP Rate Limit Rx Pings");
	rule.m_eAction = eFILTER_RATE_LIMIT;
	rule.m_eDirection = eFILTER_RECEIVE;
	rule.m_protocol.eProto = eFILTER_ICMP;
	rule.m_protocol.nSubTypeArrays[FILTER_ICMP_TYPE_INDEX].Add(FILTER_ICMP_ECHO);
	rule.m_rate.ulPacketsPerSecond = 2;
	rule.m_rate.ulMaxHosts = 10;
	if (!m_pPacketFilter->AddRule(rule))
		LOGERRSB(CLogger::eLOG_NETMGR, "Unable to add "_LS_" Rule.\n", (LPCXSTR)rule.m_sName);

	rule.Reset();
	rule.m_sName = TXT("UDP Rate limit");
	rule.m_eAction = eFILTER_RATE_LIMIT;
	rule.m_eDirection = eFILTER_RECEIVE;
	rule.m_protocol.eProto = eFILTER_UDP;
	rule.m_rate.ulPacketsPerSecond = 2100;
	rule.m_rate.ulMaxHosts = 0;
	if (!m_pPacketFilter->AddRule(rule))
		LOGERRSB(CLogger::eLOG_NETMGR, "Unable to add "_LS_" Rule.\n", (LPCXSTR)rule.m_sName);

	rule.Reset();
	rule.m_sName = TXT("SNMP Rate limit");
	rule.m_eAction = eFILTER_RATE_LIMIT;
	rule.m_eDirection = eFILTER_RECEIVE;
	rule.m_protocol.eProto = eFILTER_UDP;
	rule.m_rate.ulPacketsPerSecond = MAX_SNMP_REQUESTS_PER_SEC;
	rule.m_rate.ulMaxHosts = 0;
	rule.m_dstAddress.usPort = 161;
	if (!m_pPacketFilter->AddRule(rule))
		LOGERRSB(CLogger::eLOG_NETMGR, "Unable to add "_LS_" Rule.\n", (LPCXSTR)rule.m_sName);


	return CheckFilterRules();
}

//////////////////////////////////////////////////////////////////////////

bool CNetworkManager::RemovePacketObserverRuleByName(const CString& sRuleName)
{
	return RemovePacketFilterRule(sRuleName);
}

//////////////////////////////////////////////////////////////////////////

bool CNetworkManager::AddPacketObserver(IPacketObserver* pObserver, const CFilterRule& observerRule)
{
	CSyncAutoLock autoLock(m_Lock);
	
	if (!m_pPacketFilter)
	{
		return false;
	}

	if (!m_pPacketFilter->AddRule(observerRule))
	{
		LOGERRSB(CLogger::eLOG_NETMGR, "Failed to add observe rule in the Network Manager.\n");
		return false;
	}

	m_pPacketFilter->AddPacketObserver(pObserver);	
	
	return true;
}

//////////////////////////////////////////////////////////////////////////

bool CNetworkManager::AddPacketFilterRule(const CFilterRule & Rule)
{
	CSyncAutoLock autoLock(m_Lock);
	
	if (!m_pPacketFilter)
	{
		return false;
	}

	if (!m_pPacketFilter->AddRule(Rule))
	{		
		LOGDBGHSB(CLogger::eLOG_NETMGR, "Failed to Add Filter rule "_LS_" in the Network Manager.\n", (LPCXSTR)Rule.m_sName);
		return false;
	}

	LOGDBGHSB(CLogger::eLOG_NETMGR, "Added Filter rule "_LS_" in the Network Manager.\n", (LPCXSTR)Rule.m_sName);
	return true;
}

//////////////////////////////////////////////////////////////////////////

bool CNetworkManager::RemovePacketFilterRule(const  CString & sRuleName)
{
	CSyncAutoLock autoLock(m_Lock);

	if (!m_pPacketFilter)
	{
		return false;
	}

	if(!m_pPacketFilter->RemoveRuleByName(sRuleName))
	{
		LOGWRNSB(CLogger::eLOG_NETMGR, "Failed to Remove Filter rule "_LS_" in the Network Manager.\n", (LPCXSTR)sRuleName);
		return false;
	}
	
	LOGDBGHSB(CLogger::eLOG_NETMGR, "Removed Filter rule "_LS_" in the Network Manager.\n", (LPCXSTR)sRuleName);
	return true;
}

//////////////////////////////////////////////////////////////////////////

void CNetworkManager::RemovePacketObserver(IPacketObserver *pObserver)
{
	CSyncAutoLock autoLock(m_Lock);

	if (!m_pPacketFilter)
	{
		return;
	}

	m_pPacketFilter->RemovePacketObserver(pObserver);
}

//////////////////////////////////////////////////////////////////////////
// Update the dynamic filtering rules
bool CNetworkManager::CheckFilterRules()
{
#if defined(PLATFORM_ANDROID)
    // Summit implements its own packet filtering based on these rules
    // (see kernel_imx/drivers/avaya/kernel_module/nf_avaya_packet_filtering.c)
    // The packet filtering rules in the case of 96x1 gets applied during initilization here
    // In the case of summit it gets applied during platform initialization 
    // from nf_avaya_packet_filtering_open
    return true;
#endif
	if ( !m_pPacketFilter )
	{
		return false;
	}

	CConfigurationManager& config= CConfigurationManager::Instance();
	int nIcmpDestUnreach, nIcmpRedirect;
	CFilterRule rule;

	// 2 packests per second Sync
	rule.Reset();
	rule.m_sName =RULE_TCP_SYN_FLAG;
	rule.m_eAction = eFILTER_RATE_LIMIT;
	rule.m_eDirection = eFILTER_RECEIVE;
	rule.m_protocol.eProto = eFILTER_TCP;
	rule.m_protocol.nSubTypeArrays[FILTER_TCP_FLAG_INDEX].Add(FILTER_TCP_SYN_FLAG);
	rule.m_rate.ulPacketsPerSecond = 2;
	rule.m_rate.ulMaxHosts = 0;
	if (!m_pPacketFilter->UpdateRuleByName(rule))
	{
		LOGERRSB(CLogger::eLOG_NETMGR, "Unable to add "_LS_" Rule.\n", (LPCXSTR)rule.m_sName);
	}

	rule.Reset();
	rule.m_sName = RULE_TCP_RST_ACK_FLAG;
	rule.m_eAction = eFILTER_DROP;
	rule.m_eDirection = eFILTER_TRANSMIT;
	rule.m_protocol.eProto = eFILTER_TCP;
	rule.m_protocol.nSubTypeArrays[FILTER_TCP_FLAG_INDEX].Add(FILTER_TCP_RESET_FLAG | FILTER_TCP_ACK_FLAG);
	if (!m_pPacketFilter->UpdateRuleByName(rule))
	{
		LOGERRSB(CLogger::eLOG_NETMGR, "Unable to add "_LS_" Rule.\n", (LPCXSTR)rule.m_sName);
	}

	rule.Reset();
	rule.m_sName = "BroadCast rate limit";
	rule.m_eAction = eFILTER_RATE_LIMIT;
	rule.m_eDirection = eFILTER_RECEIVE;
	rule.m_protocol.eProto = eFILTER_IP;
	rule.m_rate.ulPacketsPerSecond = 0;
	rule.m_rate.ulMaxHosts = 0;
	rule.m_dstAddress.ulAddress= 0xffffffff;
	if (!m_pPacketFilter->UpdateRuleByName(rule))
	{
		LOGERRSB(CLogger::eLOG_NETMGR, "Unable to add "_LS_" Rule.\n", (LPCXSTR)rule.m_sName);
	}

	rule.Reset();
	rule.m_sName = "BroadCast DHCP No rate limit";
	rule.m_eAction = eFILTER_NO_RATE_LIMIT;
	rule.m_eDirection = eFILTER_RECEIVE;
	rule.m_protocol.eProto = eFILTER_UDP;
	rule.m_dstAddress.usPort = 68;
	if (!m_pPacketFilter->UpdateRuleByName(rule))
	{
		LOGERRSB(CLogger::eLOG_NETMGR, "Unable to add "_LS_" Rule.\n", (LPCXSTR)rule.m_sName);
	}
	
	// Handle ICMP Destination Unreachables
	if(config.GetParameter(eCONFIG_ICMP_DEST_UNREACHABLE_GENERATION, nIcmpDestUnreach)!= RC_SUCCESS)
	{
		LOGERRSB(CLogger::eLOG_NETMGR, "Unable to get ICMP DU from Config Mgr.\n");
		return false;
	}
	rule.Reset();
	rule.m_sName = FILTER_RULE_NAME_ICMPDU;
	rule.m_eAction = eFILTER_ACCEPT;
	rule.m_eDirection = eFILTER_TRANSMIT;
	rule.m_protocol.eProto = eFILTER_ICMP;
	rule.m_protocol.nSubTypeArrays[FILTER_ICMP_TYPE_INDEX].Add(FILTER_ICMP_UNREACH);
	if (nIcmpDestUnreach == (int)eICMPDU_ON)
	{
		if (!m_pPacketFilter->UpdateRuleByName(rule))
		{
			LOGERRSB(CLogger::eLOG_NETMGR, "Unable to add "_LS_" Rule.\n", (LPCXSTR)rule.m_sName);
		}
	}
	else if (nIcmpDestUnreach == (int)eICMPDU_TRACERT)
	{
		rule.m_protocol.nSubTypeArrays[FILTER_ICMP_CODE_INDEX].Add(FILTER_ICMP_UNREACH_PORT);
		rule.m_protocol.nSubTypeArrays[FILTER_ICMP_PAYLOAD_INDEX].Add(eFILTER_UDP);
		rule.m_dstAddress.usPort      = FILTER_TRACERT_PORT_MIN;
		rule.m_dstAddress.usPortRange = FILTER_TRACERT_PORT_RANGE;
		if (!m_pPacketFilter->UpdateRuleByName(rule))
		{
			LOGERRSB(CLogger::eLOG_NETMGR, "Unable to add "_LS_" Rule.\n", (LPCXSTR)rule.m_sName);
		}
	}
	else if (nIcmpDestUnreach == (int)eICMPDU_OFF)
	{
		m_pPacketFilter->RemoveRuleByName(rule.m_sName);
	}
	else
	{
		// unknown ICMPDU value
		LOGDBGSB(CLogger::eLOG_NETMGR, "Unknown ICMP DU value: %d.\n",nIcmpDestUnreach);
	}

	// Handle ICMP Redirects
	if(config.GetParameter(eCONFIG_ICMP_REDIRECT_PROCESSING, nIcmpRedirect)!= RC_SUCCESS)
	{
		LOGERRSB(CLogger::eLOG_NETMGR, "Unable to get ICMP Redirect from Config Mgr.\n");
		return false;
	}
	rule.Reset();
	rule.m_sName = FILTER_RULE_NAME_ICMPRED;
	if (nIcmpRedirect == (int)eICMPRED_ON)
	{
		rule.m_eAction = eFILTER_ACCEPT;
		rule.m_eDirection = eFILTER_RECEIVE;
		rule.m_protocol.eProto = eFILTER_ICMP;
		rule.m_protocol.nSubTypeArrays[FILTER_ICMP_TYPE_INDEX].Add(FILTER_ICMP_REDIRECT);
		if (!m_pPacketFilter->UpdateRuleByName(rule))
		{
			LOGERRSB(CLogger::eLOG_NETMGR, "Unable to add "_LS_" Rule.\n", (LPCXSTR)rule.m_sName);
		}
	}
	else if (nIcmpRedirect == (int)eICMPRED_OFF)
	{
		m_pPacketFilter->RemoveRuleByName(rule.m_sName);
	}
	else
	{
		// unknown ICMPRED value
		LOGDBGSB(CLogger::eLOG_NETMGR, "Unknown ICMP RED value: %d.\n", nIcmpRedirect);
	}

	return true;
}

//////////////////////////////////////////////////////////////////////////

bool CNetworkManager::CheckMtuSize()
{
	if ( !m_pNetAdaptor )
	{
		return false;
	}

	CConfigurationManager& config= CConfigurationManager::Instance();
	int nCurrentMtuSize, nConfigMtuSize;

	if(config.GetParameter(eCONFIG_MTU_SIZE, nConfigMtuSize)!= RC_SUCCESS)
	{
		LOGERRSB(CLogger::eLOG_NETMGR, "Unable to get MTU_SIZE from Config Mgr");
		return false;
	}

	if (m_pNetAdaptor->GetMtuSize(nCurrentMtuSize) == false)
	{
		LOGERRSB(CLogger::eLOG_NETMGR, "Unable to get MTU_SIZE from selected net interface Mgr.\n");
		return false;
	}

	if (nCurrentMtuSize != nConfigMtuSize)
	{
		if (m_pNetAdaptor->SetMtuSize(nConfigMtuSize) == false)
		{
			LOGERRSB(CLogger::eLOG_NETMGR, "Unable to set MTU_SIZE to %d on selected net Interface.\n", nConfigMtuSize);
			return false;
		}
	}

	return true;
}

//////////////////////////////////////////////////////////////////////////

bool CNetworkManager::InitializeNetworkConfiguration()
{
	CConfigurationManager& config= CConfigurationManager::Instance();
	int nL2qVlan, nL2qMode;

	if (!m_pNetAdaptor)
		return false;

	// Give the adaptor(s) a chance to initialize
	if (!m_pNetAdaptor->Initialize())
		return false;

#if defined(PLATFORM_ANDROID)
   int nParamValue;
   if (CConfigurationManager::Instance().GetParameter(eCONFIG_DOT1X_MODE, nParamValue) == RC_SUCCESS)
   {
       m_n8021xMcastPassThruMode = nParamValue;
       LOGDBGHSB(CLogger::eLOG_NETMGR, "CNetworkManager::Initialize() Set m_n8021xMcastPassThruMode to %d.\n",m_n8021xMcastPassThruMode);
       if(m_pNetAdaptor)
       {
           if (false == m_pNetAdaptor->ConfigDot1xMcastPassThru(m_n8021xMcastPassThruMode))
                   LOGERRSB(CLogger::eLOG_NETMGR, "CNetworkManager::Initialize() ERROR in enabling 802.1x multicast pass-through!!!!.\n");
               else
                   LOGDBGHSB(CLogger::eLOG_NETMGR, "CNetworkManager::Initialize() Successfully enabled 802.1x multicast pass-through\n");
       }
   }
   else
   {
       m_n8021xMcastPassThruMode = 0;
       LOGERRSB(CLogger::eLOG_NETMGR, "Failed to set m_n8021xMcastPassThruMode=%d.\n",m_n8021xMcastPassThruMode);
   }
#endif

	
	if (m_pPacketFilter)
		m_pPacketFilter->Initialize();

	// Establish the initial MTU size
	CheckMtuSize();

	SetIPMode();

#if defined(PLATFORM_ANDROID)
	m_bDhcpMode = IsActiveNetworkUsingDHCP();
#endif

	//----------------------------------------
	// Ethernet
	//----------------------------------------
	if (IsActiveNetworkEthernet())
	{
		LOGDBGHSB(CLogger::eLOG_NETMGR, "CNetworkManager::InitializeNetworkConfiguration(): Network Mode: Ethernet. Initializing L2QoS and VLAN.\n");

#if !defined(PHONE_TYPE) // if(PHONE_TYPE!=J129)

#if defined(PLATFORM_ANDROID)
	  	system("setprop network.mode ethernet");
#endif
		if(config.GetParameter(eCONFIG_VLAN_ID, nL2qVlan) != RC_SUCCESS)
		{
			LOGERRSB(CLogger::eLOG_NETMGR, "CNetworkManager::InitializeNetworkConfiguration(): Unable to get VLAN ID.\n");
			return false;
		}

		// Get the configured Vlan tagging mode
		if(config.GetParameter(eCONFIG_LAYER2_QOS_MODE, nL2qMode) != RC_SUCCESS)
		{
			LOGERRSB(CLogger::eLOG_NETMGR, "CNetworkManager::InitializeNetworkConfiguration(): Unable to get NVL2Q.\n");
			return false;
		}

#if defined(PLATFORM_VXWORKS) || defined(IPPCFG_BCM1108) || defined(IPPCFG_DVF99) || defined(PLATFORM_ANDROID)
		LOGDBGHSB(CLogger::eLOG_NETMGR, "CNetworkManager::InitializeNetworkConfiguration(): Init VLAN.\n");
		if (!IVlanUtils::Instance().Initialize((etVlanMode)nL2qMode, nL2qVlan))
		{
			return false;
		}
#if defined(PLATFORM_ANDROID)
		SetVlanSeparation();
#endif
#endif
		SetVlanStatusConfigParameters();
#endif // (PHONE_TYPE!=J129)
	}

	//----------------------------------------
	// Wi-Fi
	//----------------------------------------
	else
	{
		// For Android, Wi-Fi is enabled by Android WifiManager
		LOGDBGHSB(CLogger::eLOG_NETMGR, "CNetworkManager::InitializeNetworkConfiguration(): Network Mode: Wi-Fi - Disabling Ethernet and PC ports\n");

		// WIFITBD: For Mercury, LAN port may eventually be left enabled to monitor for carrier
		m_pNetAdaptor->SetEtherLinkStatus(eETH_PORT_LAN,false);
		m_pNetAdaptor->SetEtherLinkStatus(eETH_PORT_PC,false);

#if defined(PLATFORM_ANDROID)
	  	system("setprop network.mode wifi");
#endif
	}

	// Initialize the router in use config param to "0.0.0.0"
	if (SetActiveNetworkRouterInUse(CString(TXT("0.0.0.0"))) != RC_SUCCESS)
	{
		LOGERRSB(CLogger::eLOG_NETMGR, "Unable to set Router in use.\n");
		return false;
	}

	// Extract the Hardware Address and set it in the Config Mgr
	CString sHardwareAddress = TXT("00:00:00:00:00:00");
	m_pNetAdaptor->GetHardwareAddress(sHardwareAddress);
	if(config.SetParameter(eCONFIG_OWN_MAC_ADDRESS, sHardwareAddress) != RC_SUCCESS)
	{
		LOGERRSB(CLogger::eLOG_NETMGR, "Unable to set our MAC address.\n");
		return false;
	}

	// Determine the GigE support and set the appropriate config param
	if(config.SetParameter(eCONFIG_SUPPORT_GIGABIT, m_pNetAdaptor->IsGigabitEthernetSupported()?1:0) != RC_SUCCESS)
	{
		LOGERRSB(CLogger::eLOG_NETMGR, "Unable to set Gigabit support param\n");
		return false;
	}

	// Due to security issues:
	// Run the telnet service only when we are in a development environment
	if (config.GetBoolParameter(eCONFIG_DEBUG_DEV_TOOLS_ENABLED, false))
	{
		if (m_pNetAdaptor->StartTelnetService(1) == false)
		{
			LOGERRSB(CLogger::eLOG_NETMGR, "Unable to start telnet server\n");
			return false;
		}
		else
		{
			LOGDBGSB(CLogger::eLOG_NETMGR, "telnet server started\n");
		}
	}



	// Apply current modes for LAN and PC ports
	if (!CheckLinks())
	{
		return false;
	}

	return true;
}

//////////////////////////////////////////////////////////////////////////

bool CNetworkManager::DetermineLocalIPAddress(CString & sDestinationAddress, CString & sLocalAddress)
{
	if (m_pNetAdaptor != NULL)
	{
		return m_pNetAdaptor->DetermineLocalIPAddress(sDestinationAddress, sLocalAddress);
	}
	return false;
}

//////////////////////////////////////////////////////////////////////////

void CNetworkManager::UpdateNetworkConfiguration()
{
	LOGDBGHSB(CLogger::eLOG_NETMGR, "CNetworkManager::UpdateNetworkConfiguration().\n");
	m_bNetworkConfigUpdateDuringDHCP = ((m_eDhcpStatus == RC_INITIALIZED) || 
										(m_eDhcpStatus == RC_IN_PROGRESS) || 
										(m_eDhcpStatus == RC_BUSY));
	CConfigurationManager& rConfig = CConfigurationManager::Instance();

	// If m_bNetworkConfigUpdateDuringDHCP is true it means we requested the dhclient to send a DHCP Discovery to the network.
	if (m_bNetworkConfigUpdateDuringDHCP)
	{
		LOGDBGHSB(CLogger::eLOG_NETMGR, "CNetworkManager::UpdateNetworkConfiguration We are still in the middle of DHCP discovery. \n");
	}
	else
	{
		// Update the Ethernet Link Settings
		CheckLinks();
#if defined(IPPCFG_BCM1108) || defined(IPPCFG_DVF99)
		if ((!m_bDhcpDone) && (IsActiveNetworkEthernet()))
		{
			// Unlock the startup thread
			m_linkModeUpdateByDhcp.Set();
		}
#endif
	}

	// 
	// Check for a change in 802.1Q VLAN tagging parameters
	//
#if !defined(PHONE_TYPE)
	etVlanAction nL2QosAction = CheckNewL2Qos();
	if (nL2QosAction != eNO_ACTION)
	{
	
#if defined(IPPCFG_BCM1108) || defined(IPPCFG_DVF99)
		if (IsActiveNetworkEthernet())
		{
			if (!m_bDhcpDone && !m_bNetworkConfigUpdateDuringDHCP) 
			{
				m_bSwitchVlan = true;
				LOGDBGHSB(CLogger::eLOG_NETMGR, "CNetworkManager::UpdateNetworkConfiguration New L2Q parameters. Resetting Dhcp\n");
				Control::CAdaptorManager::Instance().SendDHCPRelease();

				if ((nL2QosAction == eTAGGING_OFF) ||
					(nL2QosAction == eTAGGING_RESET))
				{
					IVlanUtils::Instance().SetGlobalTagging(false, 0);
				}
				if ((nL2QosAction == eTAGGING_ON) ||
					(nL2QosAction == eTAGGING_RESET))
				{
					int nNewL2qVlan = rConfig.GetPersistentIntParameter(eCONFIG_VLAN_ID);

					//Increment the reboot count as we are doing the soft reset here.
					int nRestartCount = rConfig.GetPersistentIntParameter(eCONFIG_RESTART_COUNTER);
					rConfig.SetParameter(eCONFIG_RESTART_COUNTER, ++nRestartCount);

					m_bIsLinkModeUpdatedByDhcp = false;
					m_linkModeUpdateByDhcp.Reset();

					//Create new vlan interface
					IVlanUtils::Instance().SetGlobalTagging(true, nNewL2qVlan);
				}
				m_vlanSwitch.Set();

				return;
			}
			else
			{
				//Update of VLAN ID by source other than DHCP
				LOGDBGHSB(CLogger::eLOG_NETMGR, "CNetworkManager::UpdateNetworkConfiguration New L2Q parameters. Resetting\n");

				// SPQR.RESET-501: Resetting to change VLAN
				int currentVlanId = IVlanUtils::Instance().GetGlobalVlanId();
				int newVlanId = rConfig.GetPersistentIntParameter(eCONFIG_VLAN_ID);
				LOGTRACESB(CLogger::eLOG_NETMGR, CLogger::eLOG_NOTICE, CLogger::eLOG_MESSAGE_FORMAT_1,
					".TEL RESET-501 Resetting to change from VLAN %d to VLAN %d", currentVlanId, newVlanId);
				// if VLAN source is not DHCP we should wait for idle state and reboot after call will be completed
				Restart(true); 
			}
		}
#elif PLATFORM_ANDROID
        		char command[1024];
			int nVlanTest = 0;
			memset (command, '\0', sizeof(command));
			int nNewL2qVlan = rConfig.GetPersistentIntParameter(eCONFIG_VLAN_ID);
			rConfig.GetParameter(eCONFIG_VLAN_TEST_TIMER, nVlanTest);
			snprintf(command,sizeof(command),"%s %d","setprop dhcp.vlantesttimer",nVlanTest);
			system(command);
			LOGDBGSB(CLogger::eLOG_NETMGR, "In case of Andriod Reset is not required nL2QosAction :: %d \n",nL2QosAction); 		
			if(rConfig.GetBoolParameter(eCONFIG_USE_DHCP)) 
			{
			  //Send DHCP Release message 		
			   Control::CAdaptorManager::Instance().SendDHCPRelease();
                       	   LOGDBGHSB(CLogger::eLOG_NETMGR, "DHCP mode clear the network values due to change in vlan configuration\n");
			   rConfig.CompletelyRestoreParameterDefaults(eCONFIG_ROUTER_IN_USE); 
			   rConfig.CompletelyRestoreParameterDefaults(eCONFIG_DEFAULT_GATEWAY_ADDRESS_LIST); 
		           rConfig.CompletelyRestoreParameterDefaults(eCONFIG_SUBNET_MASK); 
			}
		      	EraseIPAddress();
			rConfig.CompletelyRestoreParameterDefaults(eCONFIG_OWN_IP_ADDRESS); 
			if((nL2QosAction == eTAGGING_OFF) ||  (nL2QosAction == eTAGGING_RESET))
			{
				IVlanUtils::Instance().SetGlobalTagging(false, 0);
				if(nL2QosAction == eTAGGING_OFF)
				 {
					LOGDBGSB(CLogger::eLOG_NETMGR, "eTAGGING_OFF Make interface eth0 interface down and up\n");
					system("ifconfig eth0 down");
					system("ifconfig eth0 up");
				 }
			}
			if((nL2QosAction == eTAGGING_ON) ||  (nL2QosAction == eTAGGING_RESET))
			{
				LOGDBGSB(CLogger::eLOG_NETMGR, "In case of Andriod Reset is not required nNewL2qVlan :: %d \n",nNewL2qVlan);
				//Create new vlan interface
				IVlanUtils::Instance().SetGlobalTagging(true, nNewL2qVlan);
			}
			if(rConfig.GetBoolParameter(eCONFIG_USE_DHCP)) 
			{
			 m_eDhcpStatus= RC_INITIALIZED;
			 // restart DHCP monitoring process
			 Msg::CDhcpDiscoveryRequest requestMsg;
			 CCoreMsgManager::Instance().PutMessage(&requestMsg);
			 LOGDBGSB(CLogger::eLOG_NETMGR, "Waiting for DHCP discovery results for eth0.%d interface\n",nNewL2qVlan); //once network parameters will be retrieved by dhcpcd, dhcp-adaptor will get notified and configure parameters
			}
			//Is there any change in vlan separation
			SetVlanSeparation();
#else
		LOGDBGHSB(CLogger::eLOG_NETMGR, "CNetworkManager::UpdateNetworkConfiguration New L2Q parameters. Resetting \n");

		// SPQR.RESET-501: Resetting to change VLAN
		int currentVlanId = 0;
		rConfig.GetPersistentIntParameter(eCONFIG_VLAN_ID_IN_USE, currentVlanId);
		int newVlanId = rConfig.GetPersistentIntParameter(eCONFIG_VLAN_ID);
		LOGTRACESB(CLogger::eLOG_NETMGR, CLogger::eLOG_NOTICE, CLogger::eLOG_MESSAGE_FORMAT_1,
				".TEL RESET-501 Resetting to change from VLAN %d to VLAN %d", currentVlanId, newVlanId);

		Restart();
#endif
	}
	else if (!m_bNetworkConfigUpdateDuringDHCP)
	{
		if (IsActiveNetworkEthernet())
		{
			LOGDBGHSB(CLogger::eLOG_NETMGR, "CNetworkManager::UpdateNetworkConfiguration L2Q parameters checked.  No reset required.\n");
#if defined(IPPCFG_BCM1108) || defined(IPPCFG_DVF99)
			m_bSwitchVlan = false;
			m_vlanSwitch.Set();
#endif
			SetVlanSeparation();
		}
	}
#else	//========= for J129 only
	if (!m_bNetworkConfigUpdateDuringDHCP)
	{
		if (IsActiveNetworkEthernet())
		{
			LOGDBGHSB(CLogger::eLOG_NETMGR, "CNetworkManager::UpdateNetworkConfiguration L2Q parameters checked.  No reset required.\n");
			m_bSwitchVlan = false;
			m_vlanSwitch.Set();
		}
	}
#endif //========== #if (PHONE_TYPE!=J129)

#if defined (PLATFORM_ANDROID)
	if (IsIpEmptyOrZero(eCONFIG_ROUTER_IN_USE))
	{
		FindRouter();
	}
#endif

	if (m_bNetworkConfigUpdateDuringDHCP)
	{
		return;
	}

	SetVlanStatusConfigParameters();

	// 
	// Find and Install a default route, during startup.
	//   if there is no default router yet installed 
	//
	if (IsIpEmptyOrZero(eCONFIG_ROUTER_IN_USE) && 
		((m_eState == eNET_STARTING) ||
		 (m_eState == eNET_WAITING_FOR_DHCP)))
	{
		FindRouter();
	}

	// 
	// Perform the 802.1Q tagging check, during startup
	//
	if (m_eState == eNET_STARTING)
	{
		CheckL2QosTagging();
	}

#if defined(IPPCFG_BCM1108) || defined(IPPCFG_DVF99)
	//
	// Update DNS Parameters
	//
	CheckDNS();
#endif

	//
	// Update Packet Filter Rules
	//
	CheckFilterRules();

	//
	// Update the MTU Size
	//
	CheckMtuSize();

	SetIPMode();

	//
	// Add new update methods here.  Use the Network Manager state if necessary
	// Be careful not to create looping event conditions here.  If a Network config
	// parameter is set here a new update event may be generated
	// 
}

//////////////////////////////////////////////////////////////////////////

void CNetworkManager::ProcessStartupStatusEvent(Msg::CStartupStatusEvent* pEvent)
{
	if (pEvent->m_sStatus == TXT("start"))
	{
		// commence Network startup procedures
		m_eState = eNET_STARTING;
		Start();
	}
}

//////////////////////////////////////////////////////////////////////////

void CNetworkManager::ProcessDHCPDiscoveryResultEvent(Msg::CDhcpDiscoveryResultEvent* pEvent)
{
#if defined(PLATFORM_ANDROID)
	eReturnCode DhcpStatus = (eReturnCode)pEvent->m_nStatusCode;               /**< The current status */
	int nParamValue = 0;
	CConfigurationManager& config= CConfigurationManager::Instance();
	LOGDBGHSB(CLogger::eLOG_NETMGR, "DHCP result=%d  and m_eDhcpStatus =%d\n",DhcpStatus, m_eDhcpStatus);
	config.GetParameter(eCONFIG_NETWORK_MODE, nParamValue);
	if (nParamValue == NETWORK_MODE_ETHERNET && DhcpStatus == RC_IN_PROGRESS && DhcpStatus != m_eDhcpStatus)
	{
		if(m_eDhcpStatus == RC_TIMEDOUT)
		{
			CString sReUseIpAddress= config.GetStringParameter(eCONFIG_RE_USE_IP_ADDRESS);
			CString sReUseSubnetMask= config.GetStringParameter(eCONFIG_RE_USE_SUBNET_MASK);
			LOGDBGSB(CLogger::eLOG_NETMGR, "\n*****ProcessDHCPDiscoveryResultEvent sReUseIpAddress="_LS_"=\""_LS_"\".\n", (LPCXSTR)sReUseIpAddress, (LPCXSTR)sReUseSubnetMask);
			if (m_pNetAdaptor->SetLocalIPAddress(sReUseIpAddress, sReUseSubnetMask) == false)
			{
				LOGERRSB(CLogger::eLOG_NETMGR, "Unable to set the net interface with the local IP address in DHCP2b flow "_LS_".\n",(LPCXSTR)sReUseIpAddress);
			}
			FindRouter();
			SendReadyEvent();
		}
		else
		{
			if(m_VlanTestTimerThread.IsRunning())
			{
				m_VlanTestTimerThread.End();
			}
			if (m_VlanTestTimerThread.Start(TXT("tVlanTestTimerThread"), 
					 	    (THREADFNPTR)(VlanTestTimerThread),
						    (THREADFNARG) (this),
						    eTHREAD_PRIORITY_BACKGROUND) != 0)
			{
				LOGERRSB(CLogger::eLOG_NETMGR, "Cannot start tVlanTestTimerThread thread.\n");
			}
		}
	}
	  
	if (DhcpStatus == RC_INVALID_PARAMETER)
	{
	 SendNetEvent(NET_MSG_DHCP_ADDR_CONFLICT);
	 m_eState= eNET_STARTING;
	 LOGERRSB(CLogger::eLOG_NETMGR, "DHCP Conflict. Moving to DHCP Init state.\n");
	}
	if (DhcpStatus == RC_DHCP_NAK)
	{
	 SendNetEvent(NET_MSG_DHCP_NAK);
	 m_eState= eNET_STARTING;
	 LOGERRSB(CLogger::eLOG_NETMGR, "DHCP NAK. Moving to DHCP Init state.\n");
	}
	m_eDhcpStatus = (eReturnCode)pEvent->m_nStatusCode;
	// For IP address conflict m_eDhcpStatus = RC_INVALID_PARAMETER
#elif defined(IPPCFG_BCM1108) || defined(IPPCFG_DVF99)
	m_eDhcpStatus=(eReturnCode)pEvent->m_nStatusCode;
	LOGDBGHSB(CLogger::eLOG_NETMGR, "CNetworkManager::ProcessDHCPDiscoveryResultEvent DHCP result=%d\n", m_eDhcpStatus);
	if (m_eDhcpStatus == RC_INVALID_PARAMETER)
	{
		SendNetEvent(NET_MSG_DHCP_ADDR_CONFLICT);
		
		CConfigurationManager& rConfig = CConfigurationManager::Instance();
		int nCraftRestricion = rConfig.GetIntParameter(eCONFIG_CRAFT_PROCEDURE_RESTRICTIONS);
		if (nCraftRestricion == eCRAFT_RESTRICTED)//Craft restrictions are enabled. PROCSTAT = 1
		{
			//Turn off CRAFT restrictions until we recieve DHCP success
			rConfig.RestoreDefaultParameterValue(eCONFIG_CRAFT_PROCEDURE_RESTRICTIONS);
			m_bIsCraftEnabledInConflict = true;//Craft access enabled till DHCP Success
		}

		m_eState= eNET_STARTING;
		LOGERRSB(CLogger::eLOG_NETMGR, "CNetworkManager::ProcessDHCPDiscoveryResultEvent DHCP Conflict. Moving to DHCP Init state.\n");
	}
#else
	m_eDhcpStatus=(eReturnCode)pEvent->m_nStatusCode;
	LOGDBGHSB(CLogger::eLOG_NETMGR, "DHCP result=%d\n", m_eDhcpStatus);
	// need to reboot
	if (m_eDhcpStatus == RC_INVALID_PARAMETER)
	{
		if ( m_pNetAdaptor )
		{
			m_pNetAdaptor->SetLocalIPAddress(TXT("0.0.0.0"), TXT("255.255.255.0"));
		}
		SendNetEvent(NET_MSG_DHCP_ADDR_CONFLICT);

		CPlatform::DelayThread(10000); 
		
		m_eState= eNET_STARTING;
		LOGERRSB(CLogger::eLOG_NETMGR, "CNetworkManager::ProcessDHCPDiscoveryResultEvent DHCP Conflict rebooting\n");

		// SPQR.RESET-301: Resetting to obtain new configuration parameters
		LOGTRACESB(CLogger::eLOG_NETMGR, CLogger::eLOG_ERROR, CLogger::eLOG_MESSAGE_FORMAT_1, ".TEL RESET-301 Resetting to obtain new configuration parameters");

		Restart();
	
	}
#endif
/*
	if(pEvent->m_nStatusCode != RC_SUCCESS)
	{
		LOGERRSB(CLogger::eLOG_NETMGR, "OnMessageReceived: Unable to obtain information from the DHCP server. Proceeding with what is locally available...\n");
		// TODO: what should we really do in this case?  Restart?
	}

	// continue startup procedures
	m_eState = eNET_STARTING;

	// 122564 will resume at flowchart 2
	UpdateNetworkConfiguration();

	// update Net Mgr's internal State
	m_eState = eNET_READY;

	// send the Network Ready Event
	SendNetEvent(NET_MSG_READY);
*/
}

//////////////////////////////////////////////////////////////////////////

void CNetworkManager::ProcessConfigurationUpdatedEvent(CConfigurationUpdatedEvent* pEvent)
{
	LOGDBGHSB(CLogger::eLOG_NETMGR, "CNetworkManager::ProcessConfigurationUpdatedEvent(%d).\n", 
			pEvent->m_eConfigCategory);
	if(pEvent->m_eConfigCategory == eCONFIG_CATEGORY_NETWORK_INFO)
	{
		CConfigurationManager& config= CConfigurationManager::Instance();
#if defined(PLATFORM_ANDROID)
		int nParamValue = 0;
		bool bDhcpModeValue;
		int nDhcpstd = 0;
        	char command[1024];
		memset(command, '\0', sizeof(command));
		bDhcpModeValue = config.GetBoolParameter(Config::eCONFIG_USE_DHCP);
		LOGDBGHSB(CLogger::eLOG_NETMGR, "eCONFIG_USE_DHCP value is :: bDhcpModeValue :: %d ,m_bDhcpMode::%d\n",bDhcpModeValue,m_bDhcpMode);
		if(bDhcpModeValue != m_bDhcpMode )
		{
			//Save the updated network mode
			m_bDhcpMode = bDhcpModeValue;
			if(m_bDhcpMode)
			{
				LOGDBGHSB(CLogger::eLOG_NETMGR, "eCONFIG_USE_DHCP value changed to dhcp mode clear the network vlaues\n");
				Utils::CIntArray onlyArray;
				onlyArray.Add(eCONFIG_DEFAULT_GATEWAY_ADDRESS_LIST);
				onlyArray.Add(eCONFIG_ROUTER_IN_USE);
				onlyArray.Add(eCONFIG_SUBNET_MASK);
				config.ClearParametersFromSource(eINTERNAL,etREMOVE_OPTION_ONLY, onlyArray);
				// restart DHCP monitoring process
				Msg::CDhcpDiscoveryRequest requestMsg;
				CCoreMsgManager::Instance().PutMessage(&requestMsg);
			}
			else
			{
				//Send DHCP Release message
				Control::CAdaptorManager::Instance().SendDHCPRelease();
				config.ClearParametersFromSource(eDHCP,etREMOVE_OPTION_NONE);
			}
			EraseIPAddress();
			config.CompletelyRestoreParameterDefaults(eCONFIG_OWN_IP_ADDRESS); 
			config.SetParameter(eCONFIG_RE_USE, 0);	
			config.CompletelyRestoreParameterDefaults(eCONFIG_RE_USE_IP_ADDRESS);
			config.CompletelyRestoreParameterDefaults(eCONFIG_RE_USE_SUBNET_MASK); 
			config.CompletelyRestoreParameterDefaults(eCONFIG_RE_USE_ROUTERS_LIST); 
			config.CompletelyRestoreParameterDefaults(eCONFIG_RE_USE_LAYER_QOS_TAGGING_STATUS); 
			config.CompletelyRestoreParameterDefaults(eCONFIG_RE_USE_ROUTER_IN_USE); 
		}
		if(config.GetParameter(eCONFIG_PORT_MIRRORING, nParamValue) == RC_SUCCESS)
		{
			LOGNOTICESB(CLogger::eLOG_NETMGR, "DEBUG1: Port Mirroring : dataMangerValue=%d, m_nPortMirroring=%d.\n",nParamValue , m_nPortMirroring);
			if (nParamValue != m_nPortMirroring)
			{
				//Save the updated portMirorring mode
				m_nPortMirroring = nParamValue;
				LOGNOTICESB(CLogger::eLOG_NETMGR, "DEBUG2: Port Mirroring : dataMangerValue=%d, m_nPortMirroring=%d.\n",nParamValue , m_nPortMirroring);
				if (m_nPortMirroring == 0)
				{
					//Turn off port mirroring !!!!!.
					LOGNOTICESB(CLogger::eLOG_NETMGR, "Port Mirroring : disabling port mirroring.\n");

					if(m_pNetAdaptor)
					{
						if (false == m_pNetAdaptor->ConfigEthPortMirror(false))
							LOGERRSB(CLogger::eLOG_NETMGR, "Port Mirroring : ERROR to disable port mirroring!!!.\n");
						else
							LOGNOTICESB(CLogger::eLOG_NETMGR, "Port Mirroring : Success to disabled port .\n");
					}
				}
				else
				{
					//Turn on port mirroring from lan_port to pc_port!!!!!.
					LOGERRSB(CLogger::eLOG_NETMGR, "Port Mirroring : enabling port mirroring.\n");
					if(m_pNetAdaptor)
					{
						if (false == m_pNetAdaptor->ConfigEthPortMirror(true))
							LOGERRSB(CLogger::eLOG_NETMGR, "Port Mirroring : ERROR to enabled port mirroring!!!!.\n");
						else
							LOGNOTICESB(CLogger::eLOG_NETMGR, "Port Mirroring : Success to set port mirroring from LAN port to PC port.\n");
					}
				}
			}
		}
		else
		{
			LOGERRSB(CLogger::eLOG_NETMGR, "Unable to get port mirroring from config manager.!\n");
		}
		//////////////////////////////////////////
		nParamValue = 0;
		if(config.GetParameter(eCONFIG_NETWORK_MODE, nParamValue) == RC_SUCCESS)
		{
			if (nParamValue != m_nNetworkMode)
			{
				//Save the updated network mode
				m_nNetworkMode = nParamValue;
				if (m_nNetworkMode == NETWORK_MODE_WIFI)
				{
					//Turn off LAN and PC port. Wifi is enabled by Android WifiManager.
					LOGDBGSB(CLogger::eLOG_NETMGR, "Network Mode : WIFI. Ethernet has been disabled\n");
					IVlanUtils::Instance().SetNetworkModeChanges();
					if(bDhcpModeValue)
					 {	
					  //Send DHCP Release message
					  Control::CAdaptorManager::Instance().SendDHCPRelease();
					 }
					if(m_pNetAdaptor)
					{
		      				EraseIPAddress();
						if (false == m_pNetAdaptor->SetEtherLinkStatus(eETH_PORT_LAN,false))
							LOGERRSB(CLogger::eLOG_NETMGR, "Network Mode : ERROR to disable Link for LANPORT.\n");
						if (false == m_pNetAdaptor->SetEtherLinkStatus(eETH_PORT_PC,false))
							LOGERRSB(CLogger::eLOG_NETMGR, "Network Mode : ERROR to disable Link for PCPORT.\n");
					}
					LOGDBGSB(CLogger::eLOG_NETMGR, "Network Mode : WIFI. EtherNetState \n");
                        	        config.ClearParametersFromSource(eDHCP,etREMOVE_OPTION_NONE);
#if defined(PLATFORM_ANDROID)
	  				system("setprop network.mode wifi");
#endif
   		        	        // restart DHCP monitoring process
	                                Msg::CDhcpDiscoveryRequest requestMsg;
        	                        CCoreMsgManager::Instance().PutMessage(&requestMsg);
				}
				else
				{
					if(m_pNetAdaptor)
					{
						if (false == m_pNetAdaptor->SetEtherLinkStatus(eETH_PORT_LAN,true))
							LOGERRSB(CLogger::eLOG_NETMGR, "Network Mode : ERROR to enabled Link for LANPORT.\n");
						if (false == m_pNetAdaptor->SetEtherLinkStatus(eETH_PORT_PC,true))
							LOGERRSB(CLogger::eLOG_NETMGR, "Network Mode : ERROR to enabled Link for PCPORT.\n");
					}
					//Wifi is disabled by Android WifiManager.
					LOGDBGSB(CLogger::eLOG_NETMGR, "Network Mode : Ethernet.\n");
#if defined(PLATFORM_ANDROID)
	  				system("setprop network.mode ethernet");
#endif
                        	        config.ClearParametersFromSource(eDHCP,etREMOVE_OPTION_NONE);
				}
				config.CompletelyRestoreParameterDefaults(eCONFIG_OWN_IP_ADDRESS); 
                    		if(m_bDhcpMode)
                      		 {
				 config.CompletelyRestoreParameterDefaults(eCONFIG_ROUTER_IN_USE); 
				 config.CompletelyRestoreParameterDefaults(eCONFIG_DEFAULT_GATEWAY_ADDRESS_LIST); 
				 config.CompletelyRestoreParameterDefaults(eCONFIG_SUBNET_MASK); 
				}
			}
		}
		else
		{
			LOGERRSB(CLogger::eLOG_NETMGR, "Unable to get network mode from config manager\n");
		}
		config.GetParameter(eCONFIG_DHCP_LEASE_VIOLATION_FLAG, nDhcpstd);
		snprintf(command,sizeof(command),"%s %d","setprop dhcp.dhcpstd",nDhcpstd);
		system(command);
#endif
		// WIFITBD - Revisit after Wi-Fi API is available 
		// 1) check if the user switch Network Mode to WiFi
		// 2) set WiFi config options:
		//		config.SetParameter(eCONFIG_ACTIVE_NETWORK, eACTIVE_NETWORK_WIFI);
		//		m_eActiveNetwork = eACTIVE_NETWORK_WIFI;
		// This block can be moved to UpdateNetworkConfiguration as soon as UI part 
		// where user change Network Mode will be defined
		//
		// StartWiFiConnection()

		UpdateNetworkConfiguration();
		SetVlanSeparation();
		// If IPv6 module is not loaded and phone receives config for enabling IPv6 environment
		// or otherwise if IPv6 module loaded and phone receives config for disabling IPv6
		// phone reboots to apply new configuration
		if (((config.GetIntParameter(eCONFIG_IPV6_STAT) == 1) && (m_pNetAdaptor->GetIPv6State() == eIPV6_NOT_LOADED)) ||
			((config.GetIntParameter(eCONFIG_IPV6_STAT) == 0) && (m_pNetAdaptor->GetIPv6State() != eIPV6_NOT_LOADED)))
		{
			LOGDBGHSB(CLogger::eLOG_NETMGR, "Reboot action needed for applying new IPv6 configuration.\n");
			Restart();
		}
		if(m_pPacketFilter)
		{
			m_pPacketFilter->CacheIP(true);
#if defined(PLATFORM_ANDROID)
			if (!m_pPacketFilter->configureIcmpRules())
			{
				LOGERRSB(CLogger::eLOG_NETMGR, "Unable to configure icmp rules\n");
			}
            if (!m_pPacketFilter->configureGARPRule())
            {
                LOGERRSB(CLogger::eLOG_NETMGR, "Unable to set garp rule\n");
            }

#endif
		}

		// send the Network Config Updated Event
		//		CString sIp;
		//		GetLocalIPAddress (sIp);
		//		SendNetEvent(NET_MSG_UPDATED, sIp);
        
	}
#if defined(PLATFORM_ANDROID)
    else if (pEvent->m_eConfigCategory == eCONFIG_CATEGORY_8021_X)
    {
       int nParamValue = 0;    
       CString sDot1xStatusValue;
       CString sDot1xEapsValue;
       CConfigurationManager& config= CConfigurationManager::Instance();
       sDot1xStatusValue = config.GetStringParameter(eCONFIG_DOT1X_STATUS, DOT1X_DEFAULT);
       sDot1xEapsValue = config.GetStringParameter(eCONFIG_DOT1X_EAP_METHODS, DOT1X_EAPS_DEFAULT);
       LOGDBGHSB(CLogger::eLOG_NETMGR, "eCONFIG_DOT1X_STATUS value is :: sDot1xStatusValue :: %s ,m_sDot1xStatus::%s\n",(LPCXSTR)sDot1xStatusValue, (LPCXSTR)m_sDot1xStatus);
       if (sDot1xStatusValue != m_sDot1xStatus)
       {
    	   m_sDot1xStatus = sDot1xStatusValue;
    	   if (m_nNetworkMode == NETWORK_MODE_ETHERNET)
    	   {
    		   config.CompletelyRestoreParameterDefaults(eCONFIG_OWN_IP_ADDRESS);
    	   }
       }
       LOGDBGHSB(CLogger::eLOG_NETMGR, "eCONFIG_DOT1X_MODE value is :: sDot1xEapsValue :: %s ,m_sDot1xEaps::%s\n",(LPCXSTR)sDot1xEapsValue, (LPCXSTR)m_sDot1xEaps);
       /*
        * Check if sDot1xStatus is enabled and sDot1xEapsValue value is changed
        */
       if ((sDot1xEapsValue != m_sDot1xEaps) && m_sDot1xStatus != DOT1X_DEFAULT) {
    	   m_sDot1xEaps = sDot1xEapsValue;
    	   if (m_nNetworkMode == NETWORK_MODE_ETHERNET)
    	   {
    		   config.CompletelyRestoreParameterDefaults(eCONFIG_OWN_IP_ADDRESS);
    	   }
       }

       if(config.GetParameter(eCONFIG_DOT1X_MODE, nParamValue) == RC_SUCCESS)
       {
           if (nParamValue != m_n8021xMcastPassThruMode)
           {
               m_n8021xMcastPassThruMode = nParamValue;
               LOGDBGHSB(CLogger::eLOG_NETMGR, "ProcessConfigurationUpdatedEvent Set m_n8021xMcastPassThruMode to %d.\n",m_n8021xMcastPassThruMode);
               if(m_pNetAdaptor)
               {
                   if (false == m_pNetAdaptor->ConfigDot1xMcastPassThru(m_n8021xMcastPassThruMode))
                       LOGERRSB(CLogger::eLOG_NETMGR, "ProcessConfigurationUpdatedEvent ERROR in setting 802.1x multicast pass-through!!!!.\n");
                   else
                       LOGDBGHSB(CLogger::eLOG_NETMGR, "ProcessConfigurationUpdatedEvent Successfully configured 802.1x multicast pass-through\n");
               }
               
           }
       }
       else
       {
           LOGERRSB(CLogger::eLOG_NETMGR, "Unable to get dot1x multicast pass-through mode from config manager.!\n");
       }
       
   }
#endif
}

//////////////////////////////////////////////////////////////////////////

void CNetworkManager::ProcessLoginStatusEvent(Msg::CLoginStatusEvent* pEvent)
{
	if (pEvent->m_bRegistered)
	{
		// Set the VLAN initialization value upon successful registration
		CConfigurationManager& config = CConfigurationManager::Instance();
		int nCurrentVlanId, nTaggingStatus;

		if (IsActiveNetworkWiFi())
		{
#if defined(PLATFORM_ANDROID)
			LOGERRSB(CLogger::eLOG_NETMGR, "ProcessLoginStatusEvent No actions as network mode is Wi-Fi\n");
			return;
#endif
		}
		else
		{
			if ((config.GetParameter(eCONFIG_VLAN_ID_IN_USE, nCurrentVlanId) != RC_SUCCESS) ||
				(config.GetParameter(eCONFIG_LAYER_QOS_TAGGING_STATUS, nTaggingStatus) != RC_SUCCESS))
			{
				LOGERRSB(CLogger::eLOG_NETMGR, "Unable to get VLAN ID params\n");
				return;
			}

			LOGDBGHSB(CLogger::eLOG_NETMGR, "\n ProcessLoginStatusEvent() CONFIG_VLAN_ID_IN_USE=%d\n", 
							nCurrentVlanId);

			if (nTaggingStatus != (int)eVLAN_L2Q_STAT_OFF)
			{
				// Tagging is currently ON.  Save the VLAN ID that is in use
				if (config.SetParameter(eCONFIG_VLAN_ID_INIT_VALUE, nCurrentVlanId) != RC_SUCCESS)
				{
					LOGERRSB(CLogger::eLOG_NETMGR, "Unable to set initial VLAN ID\n");
				}
				else
				{
					LOGDBGHSB(CLogger::eLOG_NETMGR, "Set initial VLAN ID to %d on login in\n", nCurrentVlanId); 
				}
			}
			else
			{
				// Tagging is currently OFF.  Remove the VLAN ID 
				if (config.RestoreDefaultParameterValue(eCONFIG_VLAN_ID_INIT_VALUE) != RC_SUCCESS)
				{
					LOGERRSB(CLogger::eLOG_NETMGR, "Unable to restore default initial VLAN ID\n");
				}
				else
				{
					LOGDBGHSB(CLogger::eLOG_NETMGR, "Restored initial VLAN ID to default\n"); 
				}
			}
		}

		// Changes done for Persist DHCP Feature
		CString sConfiguredIPAddress = GetActiveNetworkIPAddress();
		CString sConfiguredSubnetMask;
		GetActiveNetworkSubnetMask(sConfiguredSubnetMask);
		CString sLocalp;

		CString sRouterAddress;
		if( config.GetParameter( eCONFIG_ROUTER_IN_USE, sRouterAddress) != RC_SUCCESS)		//coverity err id: 110584
		{
			LOGERRSB(CLogger::eLOG_NETMGR, "Unable to get Router in use\n");
		}
		GetLocalIPAddress (sLocalp);

		CArray<Utils::CTransportAddress> routerAddresses;

		LOGDBGSB(CLogger::eLOG_NETMGR, "Values for future use ="_LS_", sIp="_LS_"\""_LS_"\".\n", (LPCXSTR)sConfiguredIPAddress, (LPCXSTR)sLocalp, (LPCXSTR)sConfiguredSubnetMask);

		if (config.SetParameter(eCONFIG_RE_USE_IP_ADDRESS, sLocalp) != RC_SUCCESS)
		{
			LOGERRSB(CLogger::eLOG_NETMGR, "Unable to set ReUseIPaddress\n");
		}
		if (config.SetParameter(eCONFIG_RE_USE_SUBNET_MASK, sConfiguredSubnetMask) != RC_SUCCESS)
		{
			LOGERRSB(CLogger::eLOG_NETMGR, "Unable to set ReUsesubnetmask\n");
		}
		if (RC_SUCCESS != GetActiveNetworkRouterAddresses(routerAddresses))
		{
			LOGERRSB(CLogger::eLOG_NETMGR, "ProcessLoginStatusEvent(): Unable to get gateway list from Config Mgr.\n");
		}
		if(RC_SUCCESS != config.SetServerAddresses(eCONFIG_RE_USE_ROUTERS_LIST, routerAddresses))
		{
			LOGERRSB(CLogger::eLOG_NETMGR, "ProcessLoginStatusEvent(): Unable to set re use gateway list from Config Mgr.\n");
		}
		if(config.SetParameter(eCONFIG_RE_USE_ROUTER_IN_USE, sRouterAddress)!= RC_SUCCESS)
		{
			LOGERRSB(CLogger::eLOG_NETMGR, "Unable to set ReUseRouterinuse.\n");
		}
		if(config.SetParameter(eCONFIG_RE_USE_LAYER_QOS_TAGGING_STATUS, nTaggingStatus)!= RC_SUCCESS)
		{
			LOGERRSB(CLogger::eLOG_NETMGR, "Unable to set eCONFIG_RE_USE_LAYER_QOS_TAGGING_STATUS.\n");
		
		}

		if ( config.SetParameter(eCONFIG_VLAN_LIST, CString(TXT(""))) != RC_SUCCESS )
		{
			LOGERRSB(CLogger::eLOG_NETADAP, "Unable to set VLANLIST to NULL.\n");
			return;
		}
		
	}
}

//////////////////////////////////////////////////////////////////////////

void CNetworkManager::ProcessSignalSocketConnected(Msg::CSignalSocketConnected* pEvent)
{
	CFilterRule SigPacketFilterRule;	

	if((pEvent->m_eTransProtocol == eTRANSPORT_TLS)||(pEvent->m_eTransProtocol == eTRANSPORT_TCP))
	{
		SigPacketFilterRule.m_protocol.eProto = eFILTER_TCP;
	}
	else if(pEvent->m_eTransProtocol == eTRANSPORT_UDP)
	{
		SigPacketFilterRule.m_protocol.eProto = eFILTER_UDP;
	}
	else
	{
		//Unknown transport protocol
		return;
	}

	CIPAddress LocalAddress(pEvent->m_sLocalAddress);
	CIPAddress RemoteAddress(pEvent->m_sRemoteAddress);

	CString sFilterName(TXT("SIGNAL_MESSAGE_Filter_"));
	sFilterName += ((pEvent->m_sRemoteAddress) + TXT("_") + CString(pEvent->m_usRemotePort));

	// remove the old one to prevent memory leak
	RemovePacketFilterRule(sFilterName);
	
	SigPacketFilterRule.m_sName = sFilterName;	
	SigPacketFilterRule.m_eAction = eFILTER_RATE_LIMIT;
	SigPacketFilterRule.m_eDirection = eFILTER_RECEIVE;

	SigPacketFilterRule.m_dstAddress.ulAddress = LocalAddress.GetAddressInt();
	SigPacketFilterRule.m_srcAddress.ulAddress = RemoteAddress.GetAddressInt();
	SigPacketFilterRule.m_dstAddress.usPort = pEvent->m_usLocalPort;
	SigPacketFilterRule.m_srcAddress.usPort = pEvent->m_usRemotePort;

	SigPacketFilterRule.m_rate.ulPacketsPerSecond = SIGNAL_MESSAGE_RATE_LIMIT;

	AddPacketFilterRule(SigPacketFilterRule);	
}

//////////////////////////////////////////////////////////////////////////

void CNetworkManager::ProcessSignalSocketClosed(Msg::CSignalSocketClosed* pEvent)
{
	if((pEvent->m_eTransProtocol == eTRANSPORT_TLS)|| 
	   (pEvent->m_eTransProtocol == eTRANSPORT_TCP)||
	   (pEvent->m_eTransProtocol == eTRANSPORT_UDP))
	{
		CString sFilterName(TXT("SIGNAL_MESSAGE_Filter_"));
		sFilterName += ((pEvent->m_sRemoteAddress) + TXT("_") + CString(pEvent->m_usRemotePort));

		RemovePacketFilterRule(sFilterName);
	}
}

//////////////////////////////////////////////////////////////////////////

void CNetworkManager::ProcessNetworkStatusEvent(Msg::CNetworkStatusEvent* pEvent)
{
    if (pEvent->m_sType == STARTUP_MSG_USER_INTERRUPUT)
    {
        // Track user interrupts
        if (!m_bInterrupt)
        {
            m_bInterrupt= true;
            LOGDBGHSB(CLogger::eLOG_NETMGR, "Received User interrupt\n");
        }
        else
        {
            LOGDBGHSB(CLogger::eLOG_NETMGR, "Interrupt button press handle pending\n");
        }
    }
    else if (pEvent->m_sType == NET_MSG_ETH_LINK_LAN)
    {
        // track when the LAN link goes up and down
        if (pEvent->m_sData != NET_ETH_LINK_DOWN)
        {
#if defined(PLATFORM_ANDROID)
		m_bEthernetLinkStatas = true;
		system("setprop ethernet.lan.linkstatus up");
		m_eDhcpStatus= RC_INITIALIZED;
		// restart DHCP monitoring process
		Msg::CDhcpDiscoveryRequest requestMsg;
		CCoreMsgManager::Instance().PutMessage(&requestMsg);
#endif
            m_networkLinkUp.Set();
        }
        else
        {
#if defined(PLATFORM_ANDROID)
	 system("setprop ethernet.lan.linkstatus down");
	 if(m_bDhcpMode)
	 {
		m_bEthernetLinkStatas = false;
		CConfigurationManager& config = CConfigurationManager::Instance();
		config.ClearParametersFromSource(eDHCP,etREMOVE_OPTION_NONE);
		config.CompletelyRestoreParameterDefaults(eCONFIG_OWN_IP_ADDRESS); 
		config.CompletelyRestoreParameterDefaults(eCONFIG_ROUTER_IN_USE); 
		config.CompletelyRestoreParameterDefaults(eCONFIG_DEFAULT_GATEWAY_ADDRESS_LIST); 
		config.CompletelyRestoreParameterDefaults(eCONFIG_SUBNET_MASK); 
		Control::CAdaptorManager::Instance().StopDHCP();
	}
		EraseIPAddress();
	 
#endif
           m_networkLinkUp.Reset();
        }
	//Call the Changed Link callback.
	m_pNetAdaptor->EtherLinkStatusChangedCallback(eETH_PORT_LAN, (pEvent->m_sData != NET_ETH_LINK_DOWN));
    }
	else if (pEvent->m_sType == NET_MSG_ETH_LINK_PC)
    {
        //Call the Changed Link callback.
		m_pNetAdaptor->EtherLinkStatusChangedCallback(eETH_PORT_PC, (pEvent->m_sData != NET_ETH_LINK_DOWN));
    }
    //SUMMIT NetworkStatusRequest/Response
	else if ((pEvent->m_sType == STARTUP_DISP_MY_CERT_SUCCESS) || (pEvent->m_sType == STARTUP_DISP_MY_CERT_FAILURE)
			|| (pEvent->m_sType == STARTUP_DISP_MY_CERT_PENDING))
	{
		m_SecurityMgrNetworkStatusInfo.m_sType = pEvent->m_sType;
		m_SecurityMgrNetworkStatusInfo.m_sData = pEvent->m_sData;
	}
	else if(pEvent->m_sType == STARTUP_MSG_LOAD_CERTS_DONE)
	{
		LOGDBGSB(CLogger::eLOG_8021X, "CNetworkManager::STARTUP_MSG_LOAD_CERTS_DONE storing status\n");
		m_SecurityMgrLoadCertInfo.m_sType = pEvent->m_sType;
		m_SecurityMgrLoadCertInfo.m_sData = pEvent->m_sData;
	}
	else if(pEvent->m_sType == STARTUP_MSG_TRUST_CERT_SUCCESS)
	{
		LOGDBGSB(CLogger::eLOG_8021X, "CNetworkManager::STARTUP_MSG_TRUST_CERT_SUCCESS storing status\n");
		m_SecurityMgrTrustCertInfo.m_sType = pEvent->m_sType;
		m_SecurityMgrTrustCertInfo.m_sData = pEvent->m_sData;
	}
	else if (pEvent->m_sType == STARTUP_MSG_MY_CERT_SUCCESS)
	{
		LOGDBGSB(CLogger::eLOG_8021X, "CNetworkManager::STARTUP_MSG_TRUST_CERT_SUCCESS storing status\n");
		m_SecurityMgrMyCertInfo.m_sType = pEvent->m_sType;
		m_SecurityMgrMyCertInfo.m_sData = pEvent->m_sData;
	} 
	else if (pEvent->m_sType == NET_MSG_WIFI_STATUS_CONNECTED)
	{
		m_networkLinkUp.Set(); //success - connectd to SSID
		//else m_networkLinkUp.Reset(); //failed
	}
	else if (pEvent->m_sType == NET_MSG_WIFI_SERVICE_START_FAIL)
	{
		LOGDBGSB(CLogger::eLOG_NETMGR, "CNetworkManager::NET_MSG_WIFI_SERVICE_START_FAIL\n");
		//WIFITBD StrtService failed
		//we are suspended on m_networkLinkUp - what we shoud do?
	}
	else if (pEvent->m_sType == NET_MSG_WIFI_SERVICE_START_SUCCESS)
	{
		LOGDBGSB(CLogger::eLOG_NETMGR, "CNetworkManager::NET_MSG_WIFI_SERVICE_START_SUCCESS\n");
		m_networkLinkUp.Set(); //success - wpa-suplicant has been initialized
		//else m_networkLinkUp.Reset(); //failed
	}
}

//////////////////////////////////////////////////////////////////////////
void CNetworkManager::Process8021xStatusEvent(Msg::CDot1xStatusEvent* pEvent)
{
	if (IsActiveNetworkWiFi())
	{
		return;
	}

	switch (pEvent->m_nAuthenticationStatusCode)
	{
	case RC_SUCCESS:
	case RC_CANCELLED:
		LOGDBGSB(CLogger::eLOG_8021X, "CNetworkManager::Process8021xStatusEvent SUCCESS(%d)\n", pEvent->m_nAuthenticationStatusCode);
		m_8021xAuthenticationSuccess.Set();
		break;
	case RC_FAILED:
		LOGERRSB(CLogger::eLOG_8021X, "CNetworkManager::Process8021xStatusEvent FAILED\n");
		m_8021xAuthenticationSuccess.Reset();
		break;
	default:
		break;
	}
}

//////////////////////////////////////////////////////////////////////////
void CNetworkManager::Process8021xCredentialsRequest(CDot1xCredentialsRequest* pRequest)
{
	if (IsActiveNetworkEthernet())
	{
		m_8021xAuthenticationSuccess.Reset();
	}
}

//////////////////////////////////////////////////////////////////////////
void CNetworkManager::ProcessNetworkPingRequest(Msg::CNetworkPingRequest* pRequest)
{
	// Start the network ping thread
	if (pRequest->m_nNumAttempts != 0)
	{
		// This is a new request
		if (!m_PingRequestThread.IsRunning())
		{
			// Save the info in the request, and start the ping thread
			m_pCachedPingRequest= pRequest->Clone();

			if (m_PingRequestThread.Start(TXT("tNetworkPingRequestThread"),
				(THREADFNPTR) (PingRequestThread),
				(THREADFNARG) (this),
				eTHREAD_PRIORITY_BACKGROUND, 10000) != 0)
			{
				LOGERRSB(CLogger::eLOG_NETMGR, "Cannot start PingRequest thread.\n");
				SPARK_DELETE(m_pCachedPingRequest, eMEM_MGR);
				m_pCachedPingRequest= 0;    
			}
			else
			{
				/* response sent out when the ping operation is completed
				 * from within CNetworkManager::PingRequestThread()
				 */
				return;
			}
		}
	}
	else
	{
		// This is a cancel request
		m_PingRequestThread.End();
	}

	// Acknowledge the request
	CNetworkPingResponse response;
	response.m_sRemoteAddress 	= pRequest->m_sRemoteAddress;
	response.m_nNumSent 		= 0;
	response.m_nNumReceived 	= 0;
	SendResponse(&response, pRequest);
}

//////////////////////////////////////////////////////////////////////////

THREADSIGNATURE CNetworkManager::PingRequestThread(THREADFNARG arg)
{
	CNetworkManager* pThis= (CNetworkManager*)arg;
	if ((pThis == NULL) || 
		(pThis->m_pCachedPingRequest == NULL))
	{
		return NULL;
	}

	CNetworkPingRequest* pCachedPingRequest = pThis->m_pCachedPingRequest;
	LOGDBGHSB(CLogger::eLOG_NETMGR, "CNetworkManager::PingRequestThread Ping to "_LS_"\n", (LPCXSTR)pCachedPingRequest->m_sRemoteAddress);
	int nReceived = 0;
	// perform individual pings, to allow the sequence to be interrrupted and stopped
	for (int i = 0; i < pCachedPingRequest->m_nNumAttempts; i++)
	{
		if (pThis->PingRemoteHost(pCachedPingRequest->m_sRemoteAddress))
		{
			++nReceived;
			// to avoid flooding nearby endpoints, slow down ping rate when successful
			CPlatform::DelayThread(500);
		}

		if (pThis->m_PingRequestThread.IsSignaledForShutdown())
		{
			break;
		}
	}

	if (!pThis->m_PingRequestThread.IsSignaledForShutdown())
	{
		CNetworkPingResponse response;
		response.m_sRemoteAddress 	= pCachedPingRequest->m_sRemoteAddress;
		response.m_nNumSent 		= pCachedPingRequest->m_nNumAttempts;
		response.m_nNumReceived 	= nReceived;
		pThis->SendResponse(&response, pCachedPingRequest);
	}

	// done with the message copy
	SPARK_DELETE(pCachedPingRequest, eMEM_MGR);
	pCachedPingRequest= 0;
	return (THREADRETURN) 0;

}

//////////////////////////////////////////////////////////////////////////

void CNetworkManager::SendResponse(CBaseResponse* pResponse, CBaseRequest *pRequest)
{
	pResponse->m_nSourceId	= pRequest->m_nSourceId;
	pResponse->m_nRequestId	= pRequest->m_nRequestId;
	pResponse->m_nClientId	= pRequest->m_nClientId;
	CCoreMsgManager::Instance().PutResponse(pResponse);
}

//////////////////////////////////////////////////////////////////////////

void CNetworkManager::OnMessageReceived(Msg::CBaseMessage* pMessage)
{
	CSyncAutoLock autoLock(m_Lock);

	if (!m_bInitialized)
		return;

	if (pMessage->m_nCategoryId == eCT_TIMER)
	{
		// add processing of timer messages here

		return;
	}

	switch (pMessage->m_nMessageId)
	{
	case eMSG_STARTUP_STATUS_EVENT:
		LOGDBGHSB(CLogger::eLOG_NETMGR, "CNetworkManager::OnMessageReceived() Processing eMSG_STARTUP_STATUS_EVENT\n");
		ProcessStartupStatusEvent((Msg::CStartupStatusEvent*)pMessage);
		break;

	case eMSG_DHCP_DISCOVERY_RESULT_EVENT:
		LOGDBGHSB(CLogger::eLOG_NETMGR, "CNetworkManager::OnMessageReceived() Processing eMSG_DHCP_DISCOVERY_RESULT_EVENT\n");
		ProcessDHCPDiscoveryResultEvent((Msg::CDhcpDiscoveryResultEvent*)pMessage);
		break;

	case eMSG_CONFIGURATION_UPDATED_EVENT:
		LOGDBGHSB(CLogger::eLOG_NETMGR, "CNetworkManager::OnMessageReceived() Processing eMSG_CONFIGURATION_UPDATED_EVENT\n");
		ProcessConfigurationUpdatedEvent((Msg::CConfigurationUpdatedEvent*)pMessage);
		break;

	case eMSG_LOGIN_STATUS_EVENT:
		LOGDBGHSB(CLogger::eLOG_NETMGR, "CNetworkManager::OnMessageReceived() Processing eMSG_LOGIN_STATUS_EVENT\n");
		ProcessLoginStatusEvent((Msg::CLoginStatusEvent*)pMessage);
		break;

	case eMSG_NETWORK_STATUS_EVENT:
		LOGDBGHSB(CLogger::eLOG_NETMGR, "CNetworkManager::OnMessageReceived() Processing eMSG_NETWORK_STATUS_EVENT\n");
		ProcessNetworkStatusEvent((Msg::CNetworkStatusEvent*)pMessage);
		break;

	case eMSG_NETWORK_PING_REQUEST:
		LOGDBGHSB(CLogger::eLOG_NETMGR, "CNetworkManager::OnMessageReceived() Processing eMSG_NETWORK_PING_EVENT\n");
		ProcessNetworkPingRequest((Msg::CNetworkPingRequest*)pMessage);
		break;

	case eMSG_DOT1X_CREDENTIALS_REQUEST:
		LOGDBGHSB(CLogger::eLOG_NETMGR, "CNetworkManager::OnMessageReceived() Processing eMSG_DOT1X_CREDENTIALS_REQUEST");
		Process8021xCredentialsRequest((Msg::CDot1xCredentialsRequest*)pMessage);
		break;

	case eMSG_DOT1X_STATUS_EVENT:
		LOGDBGHSB(CLogger::eLOG_NETMGR, "CNetworkManager::OnMessageReceived() Processing eMSG_DOT1X_STATUS_EVENT\n");
		Process8021xStatusEvent((Msg::CDot1xStatusEvent*)pMessage);
		break;

	case eMSG_NETWORK_STATUS_REQUEST:
		LOGDBGHSB(CLogger::eLOG_NETMGR, "CNetworkManager::OnMessageReceived() Processing eMSG_NETWORK_STATUS_REQUEST\n");
		ProcessNetworkStatusRequest((Msg::CNetworkStatusRequest*)pMessage);
		break;

	case eMSG_WIFI_CONNECT_NETWORK_REQUEST:
		LOGDBGHSB(CLogger::eLOG_NETMGR, "CNetworkManager::OnMessageReceived() Processing eMSG_WIFI_CONNECT_NETWORK_REQUEST\n");
		ProcessWiFiConnectNetworkRequest((Msg::CWifiConnectNetworkRequest*)pMessage);
		break;

	case eMSG_WIFI_CONNECT_NETWORK_RESPONSE:
		LOGDBGHSB(CLogger::eLOG_NETMGR, "CNetworkManager::OnMessageReceived() Processing eMSG_WIFI_CONNECT_NETWORK_RESPONSE\n");
		break;

	case eMSG_DOT1X_LOGOFF_RESPONSE:
		LOGDBGHSB(CLogger::eLOG_NETMGR, "CNetworkManager::OnMessageReceived(): Received eMSG_DOT1X_LOGOFF_RESPONSE\n");
		m_8021xLogoffSuccess.Set();
		break;
	case eMSG_SEND_PHONE_REPORT_REQUEST:
		ProcessPhoneReportRequest(static_cast<CSendPhoneReportRequest*>(pMessage));
		break;
	default:
		break;
	}
}

//////////////////////////////////////////////////////////////////////////

void CNetworkManager::GetSupportedMsgCategory(Utils::CIntArray& rSupportedMsgCategory, Utils::CIntArray& rIrregularSupportedMsgCategory)
{
	rSupportedMsgCategory.RemoveAll();
	rSupportedMsgCategory.Add(eCT_NETWORK);
}

//////////////////////////////////////////////////////////////////////////

void CNetworkManager::OnSignalingEvent(Msg::CBaseMessage *pMessage)
{
	if(pMessage->m_nCategoryId == eCT_SIGNAL)
	{
		if(pMessage->m_nMessageId == eSM_SIGNAL_SOCKET_CONNECTED)
		{
			LOGDBGHSB(CLogger::eLOG_NETMGR, "Received eSM_SIGNAL_SOCKET_CONNECTED event\n");
			ProcessSignalSocketConnected(static_cast<Msg::CSignalSocketConnected*>(pMessage));
		}
		else if(pMessage->m_nMessageId == eSM_SIGNAL_SOCKET_CLOSED)
		{
			LOGDBGHSB(CLogger::eLOG_NETMGR, "Received eSM_SIGNAL_SOCKET_CLOSED event\n");
			ProcessSignalSocketClosed(static_cast<Msg::CSignalSocketClosed*>(pMessage));
		}
	}
}

//////////////////////////////////////////////////////////////////////////

bool CNetworkManager::GetLocalIPAddress(CString& sOutLocalIPAddress)
{
	if (m_pNetAdaptor != NULL)
	{
		return m_pNetAdaptor->GetLocalIPAddress(sOutLocalIPAddress);
	}
	return false;
}

//////////////////////////////////////////////////////////////////////////

bool CNetworkManager::GetLinkLocalIPv6Address(CString& sOutLinkLocalIPv6Address) const
{
	if (m_pNetAdaptor != NULL)
	{
		return m_pNetAdaptor->GetLinkLocalIPv6Address(sOutLinkLocalIPv6Address);
	}
	return false;
}

//////////////////////////////////////////////////////////////////////////

bool CNetworkManager::GetGlobalIPv6AddressList(CArray<CString> &sOutIPv6AddressList) const
{
	if (m_pNetAdaptor != NULL)
	{
		return m_pNetAdaptor->GetGlobalIPv6AddressList(sOutIPv6AddressList);
	}
	return false;
}

//////////////////////////////////////////////////////////////////////////

bool CNetworkManager::GetOppositeFamilySourceAddress(const CString& sInLocalAddress, CString& sOutLocalAddress)
{
	if (m_pNetAdaptor != NULL)
	{
		return m_pNetAdaptor->GetOppositeFamilySourceAddress(sInLocalAddress, sOutLocalAddress);
	}
	return false;
}

//////////////////////////////////////////////////////////////////////////

bool CNetworkManager::GetLocalIPAddressFromNetworkAdaptor(const Utils::CString& sInNetworkAdaptorName, Utils::CString& sOutLocalIPAddress)
{
	if (m_pNetAdaptor != NULL)
	{
		return m_pNetAdaptor->GetLocalIPAddressFromNetworkAdaptor(sInNetworkAdaptorName, sOutLocalIPAddress);
	}
	return false;
}

//////////////////////////////////////////////////////////////////////////

bool CNetworkManager::GetHardwareAddressFromNetworkAdaptor(const CString& sInNetworkAdaptorName, CString& sOutHardwareAddress, const XCHAR cDelim)
{
	if (m_pNetAdaptor != NULL)
	{
		return m_pNetAdaptor->GetHardwareAddressFromNetworkAdaptor(sInNetworkAdaptorName, sOutHardwareAddress, cDelim);
	}
	return false;
}

//////////////////////////////////////////////////////////////////////////

bool CNetworkManager::GetCurrentDnsServer(CString& sName)
{
	if (m_pNetAdaptor != NULL)
	{
		return m_pNetAdaptor->GetCurrentDnsServer(sName);
	}
	return false;
}

//////////////////////////////////////////////////////////////////////////

bool CNetworkManager::GetFullyQualifiedHostName(CString& sName)
{
	if (m_pNetAdaptor != NULL)
	{
		return m_pNetAdaptor->GetFullyQualifiedHostName(sName);
	}
	return false;
}

//////////////////////////////////////////////////////////////////////////

bool CNetworkManager::GetHostName(CString& sName)
{
	if (m_pNetAdaptor != NULL)
	{
		return m_pNetAdaptor->GetHostName(sName);
	}
	return false;
}

//////////////////////////////////////////////////////////////////////////

bool CNetworkManager::GetDomainName(CString& sDomain)
{
	if (m_pNetAdaptor != NULL)
	{
		return m_pNetAdaptor->GetDomainName(sDomain);
	}
	return false;
}

//////////////////////////////////////////////////////////////////////////

bool CNetworkManager::GetMachineNameInformation(CString& sName, CString& sDomain)
{
	if (m_pNetAdaptor != NULL)
	{
		return m_pNetAdaptor->GetMachineNameInformation(sName, sDomain);
	}
	return false;
}

//////////////////////////////////////////////////////////////////////////

bool CNetworkManager::GetNetworkAdaptorList(CStringArray& sOutNetworkAdaptors)
{
	if (m_pNetAdaptor != NULL)
	{
		return m_pNetAdaptor->GetNetworkAdaptorList(sOutNetworkAdaptors);
	}
	return false;
}

//////////////////////////////////////////////////////////////////////////

bool CNetworkManager::GetNetworkAdaptorName(CString& sOutNetworkAdaptorName)
{
	if (m_pNetAdaptor != NULL)
	{
		return m_pNetAdaptor->GetNetworkAdaptorName(sOutNetworkAdaptorName);
	}
	return false;
}

//////////////////////////////////////////////////////////////////////////

bool CNetworkManager::SelectNetworkAdaptor(const CString& sAdaptorName)
{
	if (m_pNetAdaptor != NULL)
	{
		return m_pNetAdaptor->SelectNetworkAdaptor(sAdaptorName);
	}
	return false;
}

//////////////////////////////////////////////////////////////////////////

bool CNetworkManager::SetLocalIPAddress(const CString& sAdaptorName, const CString& sIPAddress, const CString& sMask)
{
	if (m_pNetAdaptor != NULL)
	{
		return m_pNetAdaptor->SetLocalIPAddress(sAdaptorName, sIPAddress, sMask);
	}
	return false;
}

//////////////////////////////////////////////////////////////////////////

bool CNetworkManager::SetDefaultRouterAddress(const CString& sRouterAddress, const CString& sDestination)
{
	if (m_pNetAdaptor != NULL)
	{
		return m_pNetAdaptor->SetDefaultRouterAddress(sRouterAddress, sDestination);
	}
	return false;
}

//////////////////////////////////////////////////////////////////////////

bool CNetworkManager::SetDnsServers(CStringArray& sServerAddresses)
{
	if (m_pNetAdaptor != NULL)
	{
		return m_pNetAdaptor->SetDnsServers(sServerAddresses);
	}
	return false;
}

//////////////////////////////////////////////////////////////////////////

bool CNetworkManager::SetDomainName(CString& sDomain)
{
	if (m_pNetAdaptor != NULL)
	{
		return m_pNetAdaptor->SetDomainName(sDomain);
	}
	return false;
}

//////////////////////////////////////////////////////////////////////////

bool CNetworkManager::EraseIPAddress()
{
	if (m_pNetAdaptor != NULL)
	{
		return m_pNetAdaptor->EraseIPAddress();
	}
	return false;
}

//////////////////////////////////////////////////////////////////////////

bool CNetworkManager::GetEtherSwitchStatus()
{
	if (m_pNetAdaptor != NULL)
	{
		return m_pNetAdaptor->GetEtherSwitchStatus();
	}
	return false;
}

//////////////////////////////////////////////////////////////////////////

bool CNetworkManager::GetEtherLinkStatus(etEthPort ePort, etEthLinkMode& eMode)
{
	if (m_pNetAdaptor != NULL)
	{
		return m_pNetAdaptor->GetEtherLinkStatus(ePort, eMode);
	}
	return false;
}

//////////////////////////////////////////////////////////////////////////

bool CNetworkManager::SetEtherLinkMode(etEthPort ePort, etEthLinkMode eMode)
{
	if (m_pNetAdaptor != NULL)
	{
		return m_pNetAdaptor->SetEtherLinkMode(ePort, eMode);
	}
	return false;
}
//////////////////////////////////////////////////////////////////////////

bool CNetworkManager::GetEtherLinkAutoMDIX(etEthPort ePort, bool& bEnabled)
{
	if (m_pNetAdaptor != NULL)
	{
		return m_pNetAdaptor->GetEtherLinkAutoMDIX(ePort, bEnabled);
	}
	return false;
}

//////////////////////////////////////////////////////////////////////////

bool CNetworkManager::SetEtherLinkAutoMDIX(etEthPort ePort, bool bEnabled)
{
	if (m_pNetAdaptor != NULL)
	{
		return m_pNetAdaptor->SetEtherLinkAutoMDIX(ePort, bEnabled);
	}
	return false;
}

//////////////////////////////////////////////////////////////////////////

bool CNetworkManager::IsValidNetworkConfig(CString& sPhoneIPAddress, CString& sSubnetMask, CString& sRouterIPAddress)
{
	CIPAddress phoneIPAddress(sPhoneIPAddress);
	CIPAddress subnetMask(sSubnetMask);
	CIPAddress routerIPAddress(sRouterIPAddress);

	if (Utils::IsLegalHostAddress(phoneIPAddress.GetAddressInt(), subnetMask.GetAddressInt()) == false)
	{
		LOGERRSB(CLogger::eLOG_NETMGR, "Local IP address is illegal: "_LS_".\n", (LPCXSTR)sPhoneIPAddress);
		SendNetEvent(NET_MSG_BAD_IP, sPhoneIPAddress);
		return false;
	}
	if (Utils::IsLegalHostAddress(routerIPAddress.GetAddressInt(), subnetMask.GetAddressInt()) == false)
	{
		LOGERRSB(CLogger::eLOG_NETMGR, "Local Router address is illegal: "_LS_"\n", (LPCXSTR)sRouterIPAddress);
		SendNetEvent(NET_MSG_BAD_ROUTER, sRouterIPAddress);
		return false;
	}
	if (Utils::IsLegalSubnetMask(subnetMask.GetAddressInt()) == false)
	{
		LOGERRSB(CLogger::eLOG_NETMGR, "Local Subnet mask is illegal: "_LS_"\n", (LPCXSTR)sSubnetMask);
		SendNetEvent(NET_MSG_BAD_SUBNET, sSubnetMask);
		return false;
	}
	if (routerIPAddress.GetAddressInt() != 0)
	{
		// Check that the IP address and the Router are on the same subnet
		if (Utils::IsSameSubnet(phoneIPAddress.GetAddressInt(), routerIPAddress.GetAddressInt(), subnetMask.GetAddressInt()) == false)
		{
			// Illegal configuration requested.  Do not proceed
			LOGERRSB(CLogger::eLOG_NETMGR, "Phone's configured IP address and router address are not on the same subnet.\n");
			SendNetEvent(NET_MSG_PROG_NEW_ROUTER);
			//Subnet Conflict. Turn off CRAFT restrictions
			CConfigurationManager::Instance().RestoreDefaultParameterValue(eCONFIG_CRAFT_PROCEDURE_RESTRICTIONS);
			return false;
		}
	}

#if !defined(PLATFORM_ANDROID)	//SUMMIT-1162 - 'arping' applet is used here, but not built in Summit yet
	//  Check if the phone's configured IP address is in use by another device on the local network
	if (m_pNetAdaptor->IsIPAddressAvailable(sPhoneIPAddress) == false)
	{
		LOGERRSB(CLogger::eLOG_NETMGR, CLogger::eLOG_MESSAGE_FORMAT_1,
					" .TEL IPADD-301 Terminating use of "_LS_" - conflict detected \n", (LPCXSTR)sPhoneIPAddress);
		// erase  conflicting address
		// flushRoutes();
		// eraseIPAddress(IntfName);       

		SendNetEvent(NET_MSG_ADDRESS_CONFLICT, sPhoneIPAddress);
		//IP Conflict. Turn off CRAFT restrictions
		CConfigurationManager::Instance().RestoreDefaultParameterValue(eCONFIG_CRAFT_PROCEDURE_RESTRICTIONS);
		return false;
	}
#endif
	return true;
}

//////////////////////////////////////////////////////////////////////////

bool CNetworkManager::FindRouter()
{
	CConfigurationManager& config= CConfigurationManager::Instance();
#if defined(PLATFORM_ANDROID)
	if (m_nNetworkMode == NETWORK_MODE_WIFI || m_bEthernetLinkStatas == false)
	 {
	   LOGDBGSB(CLogger::eLOG_NETMGR, "FindRouter(): return false as network mode is set to wifi or Ethernet link down m_bEthernetLinkStatas :: %d \n",m_bEthernetLinkStatas);
	   return false;
	 }
#endif
	// CID 122564: IPI.3.1.100: flow chart 2b "find a router"
	CArray<Utils::CTransportAddress> routerAddresses;
	LOGDBGSB(CLogger::eLOG_NETMGR, "FindRouter(): \n");
			
	if (GetActiveNetworkRouterAddresses(routerAddresses) != RC_SUCCESS)
	{
		LOGERRSB(CLogger::eLOG_NETMGR, "FindRouter(): Unable to get gateway list from Config Mgr.\n");
		return false;
	}

	int nReUse= 0;
	if (config.GetParameter(eCONFIG_RE_USE, nReUse)!= RC_SUCCESS)
	{
		LOGERRSB(CLogger::eLOG_NETMGR, "Unable to get eCONFIG_RE_USE.\n");
	}

	bool bIsNonZero = false;
	for (int nIndex = 0; nIndex<routerAddresses.GetSize(); nIndex++)
	{
		if (routerAddresses[nIndex].m_IPAddress.GetAddressInt() != 0)
			bIsNonZero = true;
	}
	if (!bIsNonZero)
	 {
		LOGERRSB(CLogger::eLOG_NETMGR, "FindRouter(): bIsNonZero is false and nReUse :: %d\n",nReUse);
		#if defined(PLATFORM_ANDROID)
		 if(nReUse == 0)
		  {
		   return false;
		  }
		#else 
		  return false;
		#endif 
	 }

	CString sCurrentIPAddress, sCurrentSubnetMask;

	if (!m_pNetAdaptor)
		return false;

	if (!m_pNetAdaptor->GetSubnetMask(sCurrentSubnetMask))
	{
		LOGERRSB(CLogger::eLOG_NETMGR, "FindRouter(): Unable to get subnet mask.\n");
		return false;
	}
	if (!m_pNetAdaptor->GetLocalIPAddress(sCurrentIPAddress))
	{
		LOGERRSB(CLogger::eLOG_NETMGR, "FindRouter(): Unable to get local IP address.\n");
		return false;
	}

	CIPAddress phoneAddress(sCurrentIPAddress);
	CIPAddress subnetMask(sCurrentSubnetMask);

	if (SetActiveNetworkRouterInUse(/*ContactStoredRouterFirst*/ true) == RC_SUCCESS)
	{
		// we've made contact.  Install the default route
		if (m_pNetAdaptor->SetDefaultRouterAddress(config.GetStringParameter(eCONFIG_ROUTER_IN_USE)) == false)
		{
			LOGERRSB(CLogger::eLOG_NETMGR, "FindRouter(): Unable to set default router.\n");
			return false;
		}
		return true;
	}

	// Flowchart 2, SparkIPI.3.1.100 for Persist DHCP changes
	if (nReUse == 1)
	{
		// Get the value of REUSE_ROUTER_IN_USE and set it as Default Router in use 
		CString sRouterInUse=TXT("0.0.0.0");

		if (config.GetParameter(eCONFIG_RE_USE_ROUTER_IN_USE, sRouterInUse)!= RC_SUCCESS)
		{
			LOGERRSB(CLogger::eLOG_NETMGR, "Unable to get Router used in last time.\n");
		}

		if (m_pNetAdaptor->SetDefaultRouterAddress(sRouterInUse) == false)
		{
			LOGERRSB(CLogger::eLOG_NETMGR, "Unable to set default route.\n");
			return false;
		}
		if (SetActiveNetworkRouterInUse(sRouterInUse) != RC_SUCCESS)
		{
			LOGERRSB(CLogger::eLOG_NETMGR, "Unable to set router in use.\n");
		}
		return true;		
	}

	// No contact was made to any of the routers
	// So just pick the first one on the same subnet
	for (int nIndex = 0; nIndex<routerAddresses.GetSize(); nIndex++)
	{
		unsigned int ulRouterAddress = routerAddresses[nIndex].m_IPAddress.GetAddressInt();

		if ((ulRouterAddress != 0) &&
			Utils::IsLegalHostAddress(ulRouterAddress, subnetMask.GetAddressInt()) &&
			Utils::IsSameSubnet(ulRouterAddress, phoneAddress.GetAddressInt(), subnetMask.GetAddressInt()))
		{
			// generate a syslog message here by rqmnt
			LOGDBGSB(CLogger::eLOG_NETMGR, "No routers replied to ARP requests\n");

			// Install the default route
			if (m_pNetAdaptor->SetDefaultRouterAddress((CString) routerAddresses[nIndex].m_IPAddress) == false)
			{
				LOGERRSB(CLogger::eLOG_NETMGR, "Unable to set default route.\n");
				return false;
			}
			if (SetActiveNetworkRouterInUse((CString) routerAddresses[nIndex].m_IPAddress) != RC_SUCCESS)
			{
				LOGERRSB(CLogger::eLOG_NETMGR, "Unable to set router in use.\n");
			}
			LOGDBGSB(CLogger::eLOG_NETMGR, "Default router installed.  IP address = "_LS_"\n", (LPCXSTR)(CString)routerAddresses[nIndex].m_IPAddress);
			return true;
		}
	}

	if(IsActiveNetworkUsingDHCP())
	{
		// generate a syslog message here by rqmnt
		LOGERRSB(CLogger::eLOG_NETMGR, "Routers address(es) provided are not on the same subnet\n");

		if (SetActiveNetworkRouterInUse(CString(TXT("0.0.0.0"))) != RC_SUCCESS)
		{
			LOGERRSB(CLogger::eLOG_NETMGR, "Unable to set router in use to '0.0.0.0'.\n");
		}
	}
	else
	{
#if defined(PLATFORM_ANDROID)
		if (SetActiveNetworkRouterInUse(CString(TXT("0.0.0.0"))) != RC_SUCCESS)
		{
			LOGERRSB(CLogger::eLOG_NETMGR, "Unable to set router in use to '0.0.0.0'.\n");
		}
#endif
		SendNetEvent(NET_MSG_SUBNET_CONFLICT);
		//Subnet Conflict. Turn off CRAFT restrictions
		CConfigurationManager::Instance().RestoreDefaultParameterValue(eCONFIG_CRAFT_PROCEDURE_RESTRICTIONS);
	}

	return false;
}

//////////////////////////////////////////////////////////////////////////

bool CNetworkManager::ContactLocalHost(const CString& sLocalHostIPAddress)
{
	CString sCurrentIPAddress, sCurrentSubnetMask;

	if (!m_pNetAdaptor)
		return false;

	if (!m_pNetAdaptor->GetSubnetMask(sCurrentSubnetMask))
	{
		LOGERRSB(CLogger::eLOG_NETMGR, "ContactLocalHost(): Unable to get subnet mask.\n");
		return false;
	}
	if (!m_pNetAdaptor->GetLocalIPAddress(sCurrentIPAddress))
	{
		LOGERRSB(CLogger::eLOG_NETMGR, "ContactLocalHost(): Unable to get local IP address.\n");
		return false;
	}

	CIPAddress phoneAddress(sCurrentIPAddress);
	CIPAddress subnetMask(sCurrentSubnetMask);
	CIPAddress hostAddress(sLocalHostIPAddress);

	if ((hostAddress.GetAddressInt() == 0) ||
		(Utils::IsLegalHostAddress(hostAddress.GetAddressInt(), subnetMask.GetAddressInt()) == false) ||
		(Utils::IsSameSubnet(hostAddress.GetAddressInt(), phoneAddress.GetAddressInt(), subnetMask.GetAddressInt()) == false))
	{

		LOGDBGSB(CLogger::eLOG_NETMGR, "ContactLocalHost(): Host is not on local subnet.\n");
		return false;
	}

	// If we can resolve the local host's IP address to its Hardware address
	// we assume that the host has been contacted
	CString sHardwareAddress;
	if (m_pNetAdaptor->ARPResolve(sLocalHostIPAddress, sHardwareAddress, FIND_ROUTER_MAX_ARPS, FIND_ROUTER_MAX_ARP_WAIT))
	{
		return true;
	}

	LOGDBGSB(CLogger::eLOG_NETMGR, "ContactLocalHost(): Local host can not be contacted.\n");
	return false;
}

//////////////////////////////////////////////////////////////////////////

bool CNetworkManager::PingRemoteHost(const CString& sLocalHostIPAddress)
{
    return m_pNetAdaptor->Ping(sLocalHostIPAddress,MAX_PING_WAIT);
}

//////////////////////////////////////////////////////////////////////////

bool CNetworkManager::IsIpEmptyOrZero(etConfigParameter eIpAddrId)
{
	CConfigurationManager& config= CConfigurationManager::Instance();

	CString sIp;

	if (config.GetParameter( eIpAddrId, sIp) != RC_SUCCESS) 
	{
        	LOGERRSB(CLogger::eLOG_NETMGR, "Unable to get IP\n");
		return true;
	}
	
	if (sIp == TXT("\0"))
	{
		return true;
	}
	
	CIPAddress address(sIp);
	unsigned long lIp= address.GetAddressInt();
	if (!lIp)
	{
		return true;
	}
	return false;
}

//////////////////////////////////////////////////////////////////////////

void CNetworkManager::SendNetEvent(const XCHAR* pType, const XCHAR* pData /* = TXT("")*/)
{
	LOGDBGHSB(CLogger::eLOG_NETMGR, "CNetworkManager::SendNetEvent() Sending Net Status Event Msg. Type = "_LS_" , Data = "_LS_"\n", pType, pData);
	Msg::CNetworkStatusEvent netEvent;
	netEvent.m_sType = pType;
	netEvent.m_sData = pData;
	CCoreMsgManager::Instance().PutMessage(&netEvent);
	StoreLastSentNetEvent(pType, pData);
}

//////////////////////////////////////////////////////////////////////////

bool CNetworkManager::SendEthernetStatusMsg(etEthPort ePort, etEthLinkMode eMode)
{
	CString sSpeed;
	CString sPort;

	switch (eMode)
	{
	case eETH_LINK_MODE_DISABLED:
		sSpeed = NET_ETH_LINK_DOWN;
		break;

	case eETH_LINK_MODE_10_HALF:
	case eETH_LINK_MODE_10_FULL:
		sSpeed = NET_ETH_LINK_10;
		break;

	case eETH_LINK_MODE_100_HALF:
	case eETH_LINK_MODE_100_FULL:
		sSpeed = NET_ETH_LINK_100;
		break;

	case eETH_LINK_MODE_1000_FULL:
		sSpeed = NET_ETH_LINK_1000;
		break;

	default:
		LOGERRSB(CLogger::eLOG_NETMGR, "Eth Status Msg not sent. mode %d is invalid\n", (int)eMode);
		return false;
		break;
	}

	switch (ePort)
	{
	case eETH_PORT_LAN:
		sPort = NET_MSG_ETH_LINK_LAN;
		break;

	case eETH_PORT_PC:
		sPort = NET_MSG_ETH_LINK_PC;
		break;

	default:
		LOGERRSB(CLogger::eLOG_NETMGR, "Eth Status Msg not sent. port %d is invalid\n", (int)ePort);
		return false;
		break;
	}

	CString sDuplex;
	if ((eMode == eETH_LINK_MODE_10_HALF) || (eMode == eETH_LINK_MODE_100_HALF))
	{
		sDuplex = TXT("half-duplex");
	}
	else
	{
		sDuplex = TXT("full-duplex");
	}
	if (ePort == eETH_PORT_LAN)
	{
		if (sSpeed == NET_ETH_LINK_DOWN)
		{
			LOGTRACESB(CLogger::eLOG_NETMGR, CLogger::eLOG_ERROR, CLogger::eLOG_MESSAGE_FORMAT_1, ".TEL PHY1-301 Ethernet line interface link lost\n");
		}
		else
		{
			LOGDBGSB(CLogger::eLOG_NETMGR, CLogger::eLOG_MESSAGE_FORMAT_1, ".TEL PHY1-601 "_LS_" "_LS_" link established on the Ethernet line interface\n", sSpeed.GetBuffer(), sDuplex.GetBuffer());
		}
	}
	else if (ePort == eETH_PORT_PC)
	{
		if (sSpeed == NET_ETH_LINK_DOWN)
		{
			LOGDBGSB(CLogger::eLOG_NETMGR, CLogger::eLOG_MESSAGE_FORMAT_1, ".TEL PHY2-601 Secondary Ethernet interface link lost\n");
		}
		else
		{
			LOGDBGSB(CLogger::eLOG_NETMGR, CLogger::eLOG_MESSAGE_FORMAT_1, ".TEL PHY2-602 "_LS_" "_LS_" link established on the secondary Ethernet interface\n", sSpeed.GetBuffer(), sDuplex.GetBuffer());
		}
	}

	SendNetEvent((const XCHAR*)sPort, (const XCHAR*)sSpeed);
	return true;
}

//////////////////////////////////////////////////////////////////////////

bool CNetworkManager::IsDhcpDone()
{
	bool bDone = true;

	if (m_bReboot)
	{
		return bDone;
	}

	if (m_eDhcpStatus == RC_SUCCESS)
	{
		m_eState = eNET_STARTING;
	}
	else if ((m_eDhcpStatus == RC_IN_PROGRESS) || 
			 (m_eDhcpStatus == RC_BUSY) ||
			 (m_eDhcpStatus == RC_INITIALIZED)||
			 (m_eDhcpStatus == RC_UNKNOWN))
	{
		bDone = false;
	}
	else if (m_eDhcpStatus == RC_FAILED)
	{
		LOGDBGHSB(CLogger::eLOG_NETMGR, "CNetworkManager::IsDhcpDone Cannot obtain information from the DHCP server %d\n", m_eDhcpStatus);
		m_eState = eNET_STARTING;
		bDone = false;
	}
	else if (m_eDhcpStatus == RC_INVALID_PARAMETER)
	{
#if !defined(PLATFORM_ANDROID)
		SendNetEvent(NET_MSG_DHCP_ADDR_CONFLICT);
		m_eState = eNET_STARTING;
		bDone = false;
		LOGDBGHSB(CLogger::eLOG_NETMGR, "DHCP address conflict %d\n", m_eDhcpStatus);
		m_eState = eNET_STARTING;
#endif
		bDone = false;
	}

	LOGDBGHSB(CLogger::eLOG_NETMGR, "CNetworkManager::IsDhcpDone %d\n", bDone);
	return bDone;
}

//////////////////////////////////////////////////////////////////////////

bool CNetworkManager::DhcpVlanTest()
{
	CConfigurationManager& config= CConfigurationManager::Instance();
	int nL2qVlan, nVlanTest, nNvl2q;

	nL2qVlan = config.GetPersistentIntParameter(eCONFIG_VLAN_ID);
	if ((config.GetParameter(eCONFIG_VLAN_TEST_TIMER, nVlanTest)  != RC_SUCCESS) ||
		(config.GetParameter(eCONFIG_LAYER2_QOS_MODE, nNvl2q) != RC_SUCCESS ))
	{
		LOGERRSB(CLogger::eLOG_NETMGR, "Unable to get some L2Q params\n");
		return false;
	}
	
	LOGDBGHSB(CLogger::eLOG_NETMGR, "nL2qVlan=%d, nVlanTest=%d, nNvl2q=%d\n", 
							nL2qVlan, 
							nVlanTest,
							nNvl2q);
	m_nDhcpTimer= 0;

#if defined(PLATFORM_VXWORKS) || defined(IPPCFG_BCM1108) || defined(IPPCFG_DVF99)

	// for not-Android devices - if the network is Wi-Fi - ignore dhcp vlan test
	if (IsActiveNetworkWiFi())
	{
		return true;
	}

	m_eDhcpStatus = RC_INITIALIZED;
	etVlanStat eCurrentTaggingStatus = IVlanUtils::Instance().GetGlobalTaggingStatus();
// TBD: need to be removed, only for debugging purpose
	int vlan1, vlan2;
	if ((config.GetParameter(eCONFIG_VLAN_ID_IN_USE, vlan1) != RC_SUCCESS) ||
		(config.GetParameter(eCONFIG_VLAN_ID_INIT_VALUE, vlan2) != RC_SUCCESS)) 
	{
		LOGERRSB(CLogger::eLOG_NETMGR, "Unable to get VLAN ID params\n");
		return false;
	}
	LOGDBGHSB(CLogger::eLOG_NETMGR, "CNetworkManager::DhcpVlanTest() eCONFIG_VLAN_ID_IN_USE=%d, eCONFIG_VLAN_ID_INIT_VALUE=%d\n", 
						vlan1, vlan2);

	LOGDBGHSB(CLogger::eLOG_NETMGR, "CNetworkManager::DhcpVlanTest() nL2qStat=%d, nL2qVlan=%d, nVlanTest=%d, nNvl2q=%d\n", 
							(int)eCurrentTaggingStatus, 
							nL2qVlan, 
							nVlanTest,
							nNvl2q);

	if ((eCurrentTaggingStatus == eVLAN_L2Q_STAT_ON) && (nL2qVlan > 0) && (nVlanTest > 0))
	{
		while (m_nDhcpTimer < nVlanTest)
		{
			if (IsDhcpDone())
			{
				return true;
			}
			else
			{
				if ((m_nDhcpTimer % DHCP_RETRANSMISSION_TIME) == 0)
				{
					if ((m_eDhcpStatus != RC_IN_PROGRESS) &&
						(m_eDhcpStatus != RC_BUSY) &&
						(m_eDhcpStatus != RC_SUCCESS))
					{
						LOGERRSB(CLogger::eLOG_NETMGR, "CNetworkManager::DhcpVlanTest Retransmission DHCP.\n");
						// restart DHCP process 
						Msg::CDhcpDiscoveryRequest requestMsg;
						CCoreMsgManager::Instance().PutMessage(&requestMsg);
						LOGDBGHSB(CLogger::eLOG_NETMGR, "CNetworkManager::DhcpVlanTest Waiting for DHCP discovery results.\n");
						// update Net Mgr's internal State
						m_eState = eNET_WAITING_FOR_DHCP;
						// m_eDhcpStatus may have been changed by another thread, reassign it
						m_eDhcpStatus = RC_INITIALIZED;
					}
				}

				LOGDBGHSB(CLogger::eLOG_NETMGR, "CNetworkManager::DhcpVlanTest DHCP timer %d/%d, stat=%d, vlan=%d, status=%d\n", 
							m_nDhcpTimer, 
							nVlanTest, 
							(int)eCurrentTaggingStatus,
							nL2qVlan,
							m_eDhcpStatus);

				CPlatform::DelayThread(NETWORK_CHECK_ONE_SEC_DELAY);
				m_nDhcpTimer++;
				
				// In case of dhcp conflict restart vlan test		
				if (m_eDhcpStatus == RC_INVALID_PARAMETER)
				{
					m_nDhcpTimer = 0;
				}
	
				// wait here for Ethernet connectivity
				m_networkLinkUp.Wait();

				// send a Network DHCP status message
				CString sSeconds;
				sSeconds.Format(TXT("%d of %d (VLAN %d)"), m_nDhcpTimer, nVlanTest, nL2qVlan);
				SendNetEvent(NET_MSG_DHCP_WAIT, sSeconds);
			}
		}

		LOGDBGHSB(CLogger::eLOG_NETMGR, "CNetworkManager::DhcpVlanTest DHCP on vlan %d failed.\n", nL2qVlan);

		// Add VLAN to bad VLAN_LIST
		IVlanUtils::Instance().AddVlanInList(nL2qVlan);

		// Clear out the Vlan ID params that are not usable.
		CStringParameter param;
		param.m_sValue.Format(TXT("%d"), nL2qVlan);

		// The name of the Vlan ID parameter can be either "L2QVLAN" or "VlanId", depending on the data source.
		// So, it is necessary to call RemoveCachedParameter for both parameter names to make sure
		// that all cached values of the parameter are removed.
		param.m_sName = TXT("L2QVLAN");
		config.RemoveCachedParameter(param);
		param.m_sName = TXT("VlanId");
		config.RemoveCachedParameter(param);
		config.RestoreDefaultParameterValue(eCONFIG_VLAN_ID);

		// Reset Vlan ID to 0.
		nL2qVlan = 0;

		if (!SetGlobalTagging((nNvl2q == eVLAN_L2Q_STAT_ON), nL2qVlan))
		{
			return false;
		}

		// DHCP will continue discovery on VLAN 0
		m_nDhcpTimer= 1;
		// restart DHCP process 
		Msg::CDhcpDiscoveryRequest requestMsg;
		CCoreMsgManager::Instance().PutMessage(&requestMsg);
		LOGDBGHSB(CLogger::eLOG_NETMGR, "CNetworkManager::DhcpVlanTest Waiting for DHCP discovery results.\n");
		// update Net Mgr's internal State
		m_eState = eNET_WAITING_FOR_DHCP;
	}

	//Flow chart DHCP 2 -- New addition for R2.5
	int nReUseTimer = 0;
	if (config.SetParameter(eCONFIG_RE_USE, 0) != RC_SUCCESS)
	{
		LOGERRSB(CLogger::eLOG_NETMGR, "Unable to set ReUse value to 1\n");
	}
	if (config.GetParameter(eCONFIG_RE_USE_TIMER, nReUseTimer)!= RC_SUCCESS)
	{
		LOGERRSB(CLogger::eLOG_NETMGR, "Unable to get REUSETIMER.\n");
		return false;
	}

	
	if (nReUseTimer > 0)
	{
		CString sReUseIpAddress= config.GetStringParameter(eCONFIG_RE_USE_IP_ADDRESS);
		
		if (sReUseIpAddress == TXT("0.0.0.0") || sReUseIpAddress.IsEmpty())
		{
			//If Reuse_ip_address is 0.0.0.0 or Empty then there is no use of Reuse Timer.
			//So set it to '0'
			nReUseTimer = 0;
		}
	}

	while (true)
	{
		if (IsDhcpDone())
		{
		
			int nCurrentVlanId = config.GetPersistentIntParameter(eCONFIG_VLAN_ID);
			int nPrevGoodVlan = config.GetIntParameter(eCONFIG_VLAN_ID_INIT_VALUE);
			 
			// There are cases,where you are UP and running on Voice VLAN.
			// Now the DHCP server of voice VLAN is down and user reboots the phone.
			// First Phone tries on first Voice Vlan as it did not get response from Voice VLAN DHCP, 

			// It fall back to DATA vlan DHCP server and in SSON option it gets the VOICE VLAN pointer agian.
			// In this case, we need to reuse Previously VOICE Vlan provided values.  
			if (IVlanUtils::Instance().IsVlanInList(nCurrentVlanId) && (nCurrentVlanId == nPrevGoodVlan))
			{
				// First send a release for already aquired IP address from DATA VLAN.
				Control::CAdaptorManager::Instance().SendDHCPRelease();
				if (SetPreviousRegisteredValues())
				{
					FindRouter();
				}
				return false;
			}
			return true;
		}
		else
		{
			// If we have valid reuse parameters (Reuse time and reuse IP) then break this loop 
			// if the dhcp attempt timer exceeds reuseTimer
			if ((nReUseTimer > 0) && (m_nDhcpTimer > nReUseTimer))
			{
				break;
			}

			if ((m_nDhcpTimer % DHCP_RETRANSMISSION_TIME) == 0)
			{
				if ((m_eDhcpStatus != RC_IN_PROGRESS) &&
				    (m_eDhcpStatus != RC_BUSY) &&
				    (m_eDhcpStatus != RC_SUCCESS))
				{
					LOGERRSB(CLogger::eLOG_NETMGR, "CNetworkManager::DhcpVlanTest Retransmission DHCP.\n");
					// restart DHCP process 
					Msg::CDhcpDiscoveryRequest requestMsg;
					CCoreMsgManager::Instance().PutMessage(&requestMsg);
					LOGDBGHSB(CLogger::eLOG_NETMGR, "CNetworkManager::DhcpVlanTest Waiting for DHCP discovery results.\n");
					// update Net Mgr's internal State
					m_eState = eNET_WAITING_FOR_DHCP;
					// m_eDhcpStatus may have been changed by another thread, reassign it
					m_eDhcpStatus = RC_INITIALIZED;
				}
			}
			LOGDBGHSB(CLogger::eLOG_NETMGR, "CNetworkManager::DhcpVlanTest DHCP wait %d/%d, stat=%d, vlan=%d, status=%d\n", 
						m_nDhcpTimer, 
						nVlanTest, 
						(int)eCurrentTaggingStatus,
						nL2qVlan,
						m_eDhcpStatus);

			CPlatform::DelayThread(NETWORK_CHECK_ONE_SEC_DELAY);
 
			// wait here for Ethernet connectivity
			m_networkLinkUp.Wait();

			// send a Network DHCP status message
			CString sSeconds;
			if (nNvl2q == eVLAN_L2Q_STAT_ON)
			{
				sSeconds.Format(TXT("%d (VLAN 0)"), m_nDhcpTimer);
			}
			else
			{
				sSeconds.Format(TXT("%d"), m_nDhcpTimer);
			}
			SendNetEvent(NET_MSG_DHCP_WAIT, sSeconds);

			m_nDhcpTimer++;

			// In case of dhcp conflict restart dhcp timer
			if (m_eDhcpStatus == RC_INVALID_PARAMETER)
			{
				m_nDhcpTimer = 0;
			}
		}
	}

	//We are here as the DHCP discover was not successful and Reuse Timer is expired
	//So, reuse previously set values and unlock all the locks.
	if (SetPreviousRegisteredValues())
	{
		FindRouter();
	}
	m_bIsLinkModeUpdatedByDhcp = false;
	m_linkModeUpdateByDhcp.Set();
	return false;
#elif defined(PLATFORM_ANDROID) 
	if ((nNvl2q != eVLAN_L2Q_OFF) && (nL2qVlan >0 ) && (nVlanTest >0))
	{
	 while (m_nDhcpTimer < nVlanTest)
	   {
		CPlatform::DelayThread(NETWORK_CHECK_ONE_SEC_DELAY);
		m_nDhcpTimer++;
                LOGDBGSB(CLogger::eLOG_NETMGR, "m_nDhcpTimer :: %d and m_eDhcpStatus :: %d\n",m_nDhcpTimer,m_eDhcpStatus);
		if(m_eDhcpStatus == RC_SUCCESS)
			return true;
		if(m_bDhcpMode == 0 || m_bEthernetLinkStatas == false)
		 {
         		LOGERRSB(CLogger::eLOG_NETMGR, "Device moved to static mode return m_bDhcpMode:: %d or link down m_bEthernetLinkStatas :: %d\n",m_bDhcpMode,m_bEthernetLinkStatas);
			return true;
		 }
		// In case of dhcp conflict restart vlan test		
		if (m_eDhcpStatus == RC_INVALID_PARAMETER)
		{
		 m_nDhcpTimer = 0;
		}
	   }
	 //Add VLAN to bad VLAN_LIST
         LOGERRSB(CLogger::eLOG_NETMGR, "nL2qVlan :: %d added in bad vlan list and set vlan id to zero\n",nL2qVlan);
	 IVlanUtils::Instance().AddVlanInList(nL2qVlan);
  	 // Revert to the NULL Vlan ID
	 nL2qVlan= 0;
	 // Clear out the Vlan ID params that were not usable
	 CStringParameter param;
	 param.m_sName= TXT("L2QVLAN");
	 param.m_sValue.Format(TXT("%d"), nL2qVlan);
	 config.RemoveCachedParameter(param);
	 config.RestoreDefaultParameterValue(eCONFIG_VLAN_ID);
	}
	else
	{
         LOGERRSB(CLogger::eLOG_NETMGR, "nVlanTest :: %d is < than zero nNvl2q :: %d  nL2qVlan :: %d\n",nVlanTest,nNvl2q,nL2qVlan);
	} 	
         // DHCP will continue discovery on VLAN 0
         m_nDhcpTimer = 1;
	//Flow chart DHCP 2 -- New addition for R2.5
	int nReUseTimer = 0;
	if (config.SetParameter(eCONFIG_RE_USE, 0) != RC_SUCCESS)
	{
		LOGERRSB(CLogger::eLOG_NETMGR, "Unable to set ReUse value to 1\n");
	}
	if (config.GetParameter(eCONFIG_RE_USE_TIMER, nReUseTimer)!= RC_SUCCESS)
	{
		LOGERRSB(CLogger::eLOG_NETMGR, "Unable to get REUSETIMER.\n");
		return false;
	}
	
	if (nReUseTimer > 0)
	{
		CString sReUseIpAddress= config.GetStringParameter(eCONFIG_RE_USE_IP_ADDRESS);
		
		if (sReUseIpAddress == TXT("0.0.0.0") || sReUseIpAddress.IsEmpty())
		{
			//If Reuse_ip_address is 0.0.0.0 or Empty then there is no use of Reuse Timer.
			//So set it to '0'
			nReUseTimer = 0;
		}
	}
	if(nReUseTimer == 0)
	{
		LOGERRSB(CLogger::eLOG_NETMGR, "eCONFIG_RE_USE_TIMER is zero or eCONFIG_RE_USE_IP_ADDRESS is null return  no IP reuse \n");
		return true;
	}
	while (true)
	{
                LOGDBGSB(CLogger::eLOG_NETMGR, "m_nDhcpTimer :: %d and nReUseTimer :: %d\n",m_nDhcpTimer,nReUseTimer);
		if(m_bDhcpMode == 0 || m_bEthernetLinkStatas == false)
		 {
         		LOGERRSB(CLogger::eLOG_NETMGR, "Device moved to static mode or Ethernet Link Down m_bEthernetLinkStatas %d return no IP reuse m_bDhcpMode:: %d\n",m_bDhcpMode,m_bEthernetLinkStatas);
			return true;
		 }
		if (IsDhcpDone())
		{
			int nCurrentVlanId = config.GetPersistentIntParameter(eCONFIG_VLAN_ID);
			int nPrevGoodVlan = config.GetIntParameter(eCONFIG_VLAN_ID_INIT_VALUE);
			int nVlanMode = config.GetIntParameter(eCONFIG_LAYER2_QOS_MODE);
			if(nVlanMode == eVLAN_L2Q_OFF)
			 {
         			LOGERRSB(CLogger::eLOG_NETMGR, "Vlan is Off do not reuse the IP address %d\n",nVlanMode);
				return true;
			 }	
			// There are cases,where you are UP and running on Voice VLAN.
			// Now the DHCP server of voice VLAN is down and user reboots the phone.
			// First Phone tries on first Voice Vlan as it did not get response from Voice VLAN DHCP, 
			// It fall back to DATA vlan DHCP server and in SSON option it gets the VOICE VLAN pointer agian.
			// In this case, we need to reuse Previously VOICE Vlan provided values.  
			if (IVlanUtils::Instance().IsVlanInList(nCurrentVlanId) && (nCurrentVlanId == nPrevGoodVlan))
			{
				// First send a release for already aquired IP address from DATA VLAN.
				Control::CAdaptorManager::Instance().SendDHCPRelease();
				SetPreviousRegisteredValues();
			}
                	LOGDBGSB(CLogger::eLOG_NETMGR, "Vlan test timer return as we got IP from data vlan\n");
			return true;
		}
		else
		{
			// If we have valid reuse parameters (Reuse time and reuse IP) then break this loop 
			// if the dhcp attempt timer exceeds reuseTimer
			if ((nReUseTimer > 0) && (m_nDhcpTimer > nReUseTimer))
			{
				break;
			}

			CPlatform::DelayThread(NETWORK_CHECK_ONE_SEC_DELAY);
			m_nDhcpTimer++;
			// In case of dhcp conflict restart dhcp timer
                        if (m_eDhcpStatus == RC_INVALID_PARAMETER)
                        {
                                m_nDhcpTimer = 0;
                        }

		}
	}
	//We are here as the DHCP discover was not successful and Reuse Timer is expired
	//So, reuse previously set values and unlock all the locks.
	SetPreviousRegisteredValues();
#endif
	return true;
}

//////////////////////////////////////////////////////////////////////////

bool CNetworkManager::SetGlobalTagging(const bool bEnable, const int nL2qVlan)
{
	if (m_pNetAdaptor != NULL)
	{
		return m_pNetAdaptor->SetGlobalTagging(bEnable, nL2qVlan);
	}
	return false;
}

//////////////////////////////////////////////////////////////////////////

bool CNetworkManager::IsGlobalTaggingOn()
{
	if (m_pNetAdaptor != NULL)
	{
		return m_pNetAdaptor->IsGlobalTaggingOn();
	}
	return false;
}

//////////////////////////////////////////////////////////////////////////

bool CNetworkManager::GetGlobalVlanId(int& nVlanId)
{
	if (m_pNetAdaptor != NULL)
	{
		return m_pNetAdaptor->GetGlobalVlanId(nVlanId);
	}
	return false;
}

//////////////////////////////////////////////////////////////////////////

bool CNetworkManager::SetVlanStatusConfigParameters(void)
{
	if (m_pNetAdaptor != NULL)
	{
		return m_pNetAdaptor->SetVlanStatusConfigParameters();
	}
	return false;
}

//////////////////////////////////////////////////////////////////////////

bool CNetworkManager::SetVlanSeparation(void)
{
#if defined(PLATFORM_VXWORKS) || defined(IPPCFG_BCM1108) || defined(PLATFORM_ANDROID) || defined(IPPCFG_DVF99)
	bool bRetVal;
	if (m_pNetAdaptor != NULL)
	{
		bRetVal = m_pNetAdaptor->SetVlanSeparation();
	}

	if ((m_pPacketFilter != NULL) && !m_bAreBMcastFitersEnabled)
	{
		m_pPacketFilter->EnableBroadcastFilter();
		m_pPacketFilter->EnableMulticastFilter();
		m_bAreBMcastFitersEnabled = true;
	}
	return bRetVal;
#endif // defined(PLATFORM_VXWORKS) || defined(IPPCFG_BCM1108) || defined(IPPCFG_DVF99)
	return true;
}

//////////////////////////////////////////////////////////////////////////

bool CNetworkManager::SetPreviousRegisteredValues()
{

#if defined(IPPCFG_BCM1108) || defined(IPPCFG_DVF99) || defined(PLATFORM_ANDROID)

	//set REUSE=1 and IPADD, NETMASK, ROUTERS to REUSE_values respectively
	int nReUseTaggingStatus;
	int nReUseL2qVlan;
	CConfigurationManager& config= CConfigurationManager::Instance();
	CString sReUseIpAddress= config.GetStringParameter(eCONFIG_RE_USE_IP_ADDRESS);
	CString sReUseSubnetMask= config.GetStringParameter(eCONFIG_RE_USE_SUBNET_MASK);
	CArray<Utils::CTransportAddress> routerAddresses;
	LOGDBGSB(CLogger::eLOG_NETMGR, "\n*****SetPreviousRegisteredValues sReUseIpAddress="_LS_"=\""_LS_"\".\n", (LPCXSTR)sReUseIpAddress, (LPCXSTR)sReUseSubnetMask);
	if (config.GetParameter(eCONFIG_RE_USE_LAYER_QOS_TAGGING_STATUS, nReUseTaggingStatus) != RC_SUCCESS)
	{
		LOGERRSB(CLogger::eLOG_NETMGR, "Unable to get RE_USE_LAYER_QOS_TAGGING_STATUS\n");
		return false;
	}
#if defined(PLATFORM_ANDROID)
	int nL2qVlanMode;
	if (config.GetParameter(eCONFIG_LAYER2_QOS_MODE, nL2qVlanMode) != RC_SUCCESS)
	{
		LOGERRSB(CLogger::eLOG_NETMGR, "Unable to get eCONFIG_LAYER2_QOS_MODE\n");
		return false;
	}
	if(nL2qVlanMode == eVLAN_L2Q_OFF && nReUseTaggingStatus ==1)
	 {
		LOGERRSB(CLogger::eLOG_NETMGR, "SetPreviousRegisteredValues Vlan mode is off but reuse has tagging enabled ignore the IP reuse\n");
		return false;
	 }
#endif
	if (config.SetParameter(eCONFIG_RE_USE, 1) != RC_SUCCESS)
	{
		LOGERRSB(CLogger::eLOG_NETMGR, "Unable to set ReUse value to 1\n");
		return false;
	}
	if (config.SetParameter(eCONFIG_OWN_IP_ADDRESS, sReUseIpAddress) != RC_SUCCESS)
	{
		LOGERRSB(CLogger::eLOG_NETMGR, "Unable to set ReUseIPaddress\n");
		return false;
	}
	if (config.SetParameter(eCONFIG_SUBNET_MASK, sReUseSubnetMask) != RC_SUCCESS)
	{
		LOGERRSB(CLogger::eLOG_NETMGR, "Unable to set ReUsesubnetmask\n");
		return false;
	}
	if(RC_SUCCESS != config.GetServerAddresses(eCONFIG_RE_USE_ROUTERS_LIST, routerAddresses))
	{
		LOGERRSB(CLogger::eLOG_NETMGR, "ProcessLoginStatusEvent(): Unable to get re use gateway list from Config Mgr.\n");
		return false;
	}
	if (RC_SUCCESS != GetActiveNetworkRouterAddresses(routerAddresses))
	{
		LOGERRSB(CLogger::eLOG_NETMGR, "ProcessLoginStatusEvent(): Unable to set use gateway list from Config Mgr.\n");
		return false;
	}
	if (config.GetParameter(eCONFIG_VLAN_ID_INIT_VALUE, nReUseL2qVlan) != RC_SUCCESS)
	{
		LOGERRSB(CLogger::eLOG_NETMGR, "Unable to get eCONFIG_VLAN_ID_INIT_VALUE\n");
		return false;
	}

	LOGDBGHSB(CLogger::eLOG_NETMGR, "\n SetPreviousRegisteredValues: CONFIG_VLAN_ID_INIT_VALUE=%d  nReUseTaggingStatus=%d\n", 
						nReUseL2qVlan, nReUseTaggingStatus);
	if(nReUseTaggingStatus == 1)
	{
		if (config.SetParameter(eCONFIG_VLAN_ID, nReUseL2qVlan) != RC_SUCCESS)
		{
			LOGERRSB(CLogger::eLOG_NETMGR, "Unable to set initial VLAN ID\n");
			return false;
		}
		else
		{
			LOGDBGHSB(CLogger::eLOG_NETMGR, "SetPreviousRegisteredValues Set initial VLAN ID to %d on login in\n", nReUseL2qVlan); 
		}
	
		if (!SetGlobalTagging(true, nReUseL2qVlan))
		{
			LOGERRSB(CLogger::eLOG_NETMGR, "Unable to setGlobalTagging\n");
			return false;
		}
	}
#if defined(PLATFORM_ANDROID)
	if(nReUseTaggingStatus == 1)
	 {
	  Msg::CDhcpDiscoveryRequest dhcpRequestMsg;
	  CCoreMsgManager::Instance().PutMessage(&dhcpRequestMsg);
	  LOGDBGHSB(CLogger::eLOG_NETMGR, "Waiting for DHCP discovery results.\n");
	  // update Net Mgr's internal State
	  m_eState = eNET_WAITING_FOR_DHCP;
	  m_eDhcpStatus = RC_TIMEDOUT;
	 }
	else
	 {
	  LOGDBGHSB(CLogger::eLOG_NETMGR, "SetPreviousRegisteredValues Tagging off set IP address to device\n");
	   if (m_pNetAdaptor->SetLocalIPAddress(sReUseIpAddress, sReUseSubnetMask) == false)
	    {
		LOGERRSB(CLogger::eLOG_NETMGR, "Unable to set the net interface with the local IP address in DHCP2b flow "_LS_".\n", (LPCXSTR)sReUseIpAddress);
		return false;
	   }
	   FindRouter();
	   SendReadyEvent();
	}
#else
	if (m_pNetAdaptor->SetLocalIPAddress(sReUseIpAddress, sReUseSubnetMask) == false)
	{
		LOGERRSB(CLogger::eLOG_NETMGR, "Unable to set the net interface with the local IP address in DHCP2b flow "_LS_".\n", (LPCXSTR)sReUseIpAddress);
		return false;
	}
#endif
#endif

#if defined(IPPCFG_BCM1108) || defined(IPPCFG_DVF99)
	Msg::CDhcpDiscoveryRequest dhcpRequestMsg;
	CCoreMsgManager::Instance().PutMessage(&dhcpRequestMsg);
	LOGDBGHSB(CLogger::eLOG_NETMGR, "Waiting for DHCP discovery results.\n");
	// update Net Mgr's internal State
	m_eState = eNET_WAITING_FOR_DHCP;
	m_eDhcpStatus = RC_INITIALIZED;
	// Send request for "Extended Rebinding State" 
	Msg::CDhcpExtendedRebindRequest requestMsg;
	CCoreMsgManager::Instance().PutMessage(&requestMsg);
	while(m_eDhcpStatus != RC_SUCCESS)
	{
		CPlatform::DelayThread(1000);
	}
	m_bSwitchVlan = false;
	m_vlanSwitch.Set();
#endif
	return true;
}

//////////////////////////////////////////////////////////////////////////]

void CNetworkManager::SetIPMode()
{
	CConfigurationManager &config = CConfigurationManager::Instance();
	etIPMode eNewIPMode = eMODE_NONE;
	CString sIpv6Addr = config.GetPersistentStringParameter(eCONFIG_OWN_IPV6_ADDRESS);
	if (!sIpv6Addr.IsEmpty() &&
		(sIpv6Addr != IPV6_UNASSIGNED_ADDR) &&
		// When eCONFIG_IPV6_STAT is changed from 1 to 0, eCONFIG_OWN_IPV6_ADDRESS may contains valid IPv6 address,
		// but we need to disable IPv6 mode
		(IsIPv6Enabled())) 
	{
		eNewIPMode = eMODE_DUAL_STACK;
	}
	else
	{
		eNewIPMode = eMODE_IPV4_ONLY;
	}

	// update value in configuration manager if it is changed
	if (m_eIPMode != eNewIPMode)
	{
		eReturnCode rc = config.SetParameter(eCONFIG_IP_MODE, eNewIPMode);
		if (rc == RC_SUCCESS)
		{
			LOGDBGSB(CLogger::eLOG_NETMGR, "SetIPMode(): IP_MODE parameter is changed(old=%d, new=%d).\n", m_eIPMode, eNewIPMode);
			m_eIPMode = eNewIPMode;
		}
		else
		{
			LOGERRSB(CLogger::eLOG_NETMGR, "ERROR: Can't set IP_MODE parameter value (rc=%d)\n", rc);
		}
	}
	else
	{
		LOGDBGSB(CLogger::eLOG_NETMGR, "SetIPMode(): IP_MODE parameter is not changed(value=%d).\n", m_eIPMode);
	}
}

//////////////////////////////////////////////////////////////////////////

void CNetworkManager::SendReadyEvent()
{
	int nParamValue = 1;
	CConfigurationManager& config = CConfigurationManager::Instance();
	CString sCurrentIPAddress = GetActiveNetworkIPAddress();
	if ((sCurrentIPAddress == TXT("0.0.0.0")) || sCurrentIPAddress.IsEmpty())
	{
		LOGERRSB(CLogger::eLOG_NETMGR, "SendReadyEvent(): Local IP address is set to 0.0.0.0 .\n");
		if (!GetLocalIPAddress(sCurrentIPAddress))
		{
			LOGERRSB(CLogger::eLOG_NETMGR, "SendReadyEvent(): GetLocalIPAddress also returns local IP address as 0.0.0.0 .\n");
			return;
		}
		config.SetParameter(eCONFIG_OWN_IP_ADDRESS, sCurrentIPAddress);
	}
	LOGDBGSB(CLogger::eLOG_NETMGR, "SendReadyEvent(): Determined local IP address = "_LS_".\n", (LPCXSTR) sCurrentIPAddress);
	FindRouter();
	if (!m_bNetworkReadySend)
	{
		m_eState = eNET_READY;
		m_bNetworkReadySend = true;
		config.SetParameter(eCONFIG_NETWORK_READY_STATE, nParamValue);
		SendNetEvent(NET_MSG_READY, sCurrentIPAddress);
	}
	else
	{
		LOGERRSB(CLogger::eLOG_NETMGR, "SendReadyEvent(): NET_MSG_READY already send\n");
	}
}

////////////////////////////////////////////////////////////////////

void CNetworkManager::ComputeActiveNetwork()
{
	CConfigurationManager& configManager = CConfigurationManager::Instance();

#if defined(PLATFORM_ANDROID)
	if (configManager.GetParameter(eCONFIG_NETWORK_MODE, nParamValue) == RC_SUCCESS)
	{
		if (nParamValue != m_nNetworkMode)
		{
			// Save the updated network mode
			m_nNetworkMode = nParamValue;
		
			if (m_nNetworkMode != NETWORK_MODE_WIFI)
			{
				// Phone boots with default mode as ethernet, so we should not reach here.
				LOGERRSB(CLogger::eLOG_NETMGR, "CNetworkManager::ComputeActiveNetwork(): Network Mode : Ethernet. We should not reach here.\n");
			}
		}
	}
	else
	{
		LOGERRSB(CLogger::eLOG_NETMGR, "CNetworkManager::ComputeActiveNetwork(): Unable to get network mode from config manager\n");
	}

#else

	int nWifiStat = configManager.GetIntParameter(eCONFIG_WIFI_STAT);

	// If it is NOT a TEST MODE the code should check whether the phone support Wi-Fi or not
	// otherwise, the TestSuite should check logic of the ComputeActiveNetwork() function 
	//      regurdless of the phone's possibilities.
	if(!m_bTestMode)
	{
		if (!CAP_WiFi())
		{
			LOGDBGHSB(CLogger::eLOG_NETMGR, "CNetworkManager::ComputeActiveNetwork(): forsed reset WIFISTAT=0, CAP_WiFi()=%d, m_bTestMode=%d\n", (int)CAP_WiFi(	), (int)m_bTestMode);
			configManager.SetParameter(eCONFIG_WIFI_STAT, eWIFI_STAT_DISABLED);
			nWifiStat = eWIFI_STAT_DISABLED;
		}
		else
		{
			CString sWiFiStat, sWiFiStatConfig;
			if (configManager.GetParameterBySource(eCONFIG_WIFI_STAT, eCONFIG_XML, sWiFiStatConfig))
			{
				// Set to default and get parameter from settings file
				configManager.RestoreDefaultParameterValue(eCONFIG_WIFI_STAT);
				configManager.GetParameterBySource(eCONFIG_WIFI_STAT, eSCRIPT, sWiFiStat);
				LOGDBGH(CLogger::eLOG_NETMGR, TXT("CNetworkManager::ComputeActiveNetwork(): Set WIFISTAT to default and use value provided in settings file %ls\n"), (LPCXSTR) sWiFiStat);
				nWifiStat = sWiFiStat.IsEmpty() ? configManager.GetIntParameter(eCONFIG_WIFI_STAT) : sWiFiStat.ToInt();
			}
		}
	}

	// Wi-Fi Disabled, force Ethernet
	if(nWifiStat == eWIFI_STAT_DISABLED)
	{
		configManager.SetParameter(eCONFIG_ACTIVE_NETWORK, eACTIVE_NETWORK_ETHERNET);
	}
	// Force Wi-Fi
	else if((nWifiStat == eWIFI_STAT_UNRESTRICTED_ONLY) || (nWifiStat == eWIFI_STAT_RESTRICTED_ONLY))
	{
		configManager.SetParameter(eCONFIG_ACTIVE_NETWORK, eACTIVE_NETWORK_WIFI);
	}
	// Wi-Fi or Ethernet
	else if((nWifiStat == eWIFI_STAT_UNRESTRICTED_OR_ETHERNET) || (nWifiStat == eWIFI_STAT_RESTRICTED_OR_ETHERNET))
	{
		// use previously stored value
	}
	else
	{
		LOGERRSB(CLogger::eLOG_CONFIG, "CNetworkManager::ComputeActiveNetwork() Invalid WIFISTAT: %d\n", nWifiStat);
	}

	m_eActiveNetwork = (etActiveNetwork) configManager.GetIntParameter(eCONFIG_ACTIVE_NETWORK);
	
	LOGDBGHSB(CLogger::eLOG_NETMGR, "CNetworkManager::ComputeActiveNetwork() WIFISTAT is %d, ACTIVENETWORK set to %d\n", nWifiStat, m_eActiveNetwork);
#endif
}

///////////////////////////////////////////////////////////////////////////

bool CNetworkManager::IsActiveNetworkWiFi(void)
{
#if defined(FEATURE_WIFI)
	return (m_eActiveNetwork == eACTIVE_NETWORK_WIFI);
#elif defined(PLATFORM_ANDROID)
	return (m_nNetworkMode == NETWORK_MODE_WIFI);
#else
	return false;
#endif
}

///////////////////////////////////////////////////////////////////////////

bool CNetworkManager::IsActiveNetworkEthernet(void)
{
#if defined(FEATURE_WIFI)
	return (m_eActiveNetwork == eACTIVE_NETWORK_ETHERNET);
#elif defined(PLATFORM_ANDROID)
	return (m_nNetworkMode == NETWORK_MODE_ETHERNET);
#else
	return true;
#endif
}

///////////////////////////////////////////////////////////////////////////

bool CNetworkManager::IsActiveNetworkUsingDHCP(bool bDefVal /* = false*/)
{
	if (m_pNetAdaptor != NULL)
	{
		return m_pNetAdaptor->IsActiveNetworkUsingDHCP(bDefVal);
	}
	return false;
}

///////////////////////////////////////////////////////////////////////////

eReturnCode CNetworkManager::IsActiveNetworkUsingDHCP( CString& sDhcpValue )
{
	if (m_pNetAdaptor != NULL)
	{
		return m_pNetAdaptor->IsActiveNetworkUsingDHCP(sDhcpValue);
	}
	return RC_FAILED;
}

///////////////////////////////////////////////////////////////////////////

CString CNetworkManager::GetActiveNetworkIPAddress(const CString& sDefVal /*= TXT("")*/)
{
	if (m_pNetAdaptor != NULL)
	{
		return m_pNetAdaptor->GetActiveNetworkIPAddress(sDefVal);
	}
	return sDefVal;
}

///////////////////////////////////////////////////////////////////////////

eReturnCode CNetworkManager::GetActiveNetworkSubnetMask(CString& sValue)
{
	if (m_pNetAdaptor != NULL)
	{
		return m_pNetAdaptor->GetActiveNetworkSubnetMask(sValue);
	}
	return RC_FAILED;
}

//////////////////////////////////////////////////////////////////////////

Utils::CTransportAddress CNetworkManager::GetActiveNetworkFirstRouterAddress()
{
	if (m_pNetAdaptor != NULL)
	{
		return m_pNetAdaptor->GetActiveNetworkFirstRouterAddress();
	}
	return Utils::CTransportAddress(); //return empty class
}

//////////////////////////////////////////////////////////////////////////

eReturnCode CNetworkManager::GetActiveNetworkRouterAddresses(CArray<Utils::CTransportAddress>& list /*OUT*/)
{
	if (m_pNetAdaptor != NULL)
	{
		return m_pNetAdaptor->GetActiveNetworkRouterAddresses(list);
	}
	return RC_FAILED;
}

//////////////////////////////////////////////////////////////////////////

eReturnCode CNetworkManager::GetActiveNetworkRouterAddresses(CString& sValue /*OUT*/)
{
	if (m_pNetAdaptor != NULL)
	{
		return m_pNetAdaptor->GetActiveNetworkRouterAddresses(sValue);
	}
	return RC_FAILED;
}

//////////////////////////////////////////////////////////////////////////

eReturnCode CNetworkManager::SetActiveNetworkRouterInUse(bool bContactStoredRouterFirst)
{
	return SetActiveNetworkRouterInUse(CString(TXT("")), bContactStoredRouterFirst);
}

//////////////////////////////////////////////////////////////////////////

eReturnCode CNetworkManager::SetActiveNetworkRouterInUse(const CString& sRouterInUse, bool bContactStoredRouterFirst)
{
	CConfigurationManager& configManager = CConfigurationManager::Instance();
	CString sValue = sRouterInUse;
	eReturnCode rc = RC_FAILED;

	if (sValue == TXT(""))
	{
		CArray<Utils::CTransportAddress> routerAddresses;
		
		if (RC_SUCCESS != CNetworkManager::Instance().GetActiveNetworkRouterAddresses(routerAddresses))
		{
			LOGERRSB(CLogger::eLOG_NETMGR, "CNetworkManager::SetActiveNetworkRouterInUse(): Unable to get gateway list from Config Mgr.\n");
		}
		else if (routerAddresses.GetSize() == 0)
		{
			LOGDBGSB(CLogger::eLOG_NETMGR, "CNetworkManager::SetActiveNetworkRouterInUse(): Active Network router list is empty.\n");
		}
		else if ((routerAddresses.GetSize() == 1) && (!bContactStoredRouterFirst))
		{
			sValue = (CString) routerAddresses[0].m_IPAddress;
			rc = configManager.SetParameter(eCONFIG_ROUTER_IN_USE, sValue);
		}
		else
		{
			// Try to contact one of the router addresses
			for (int nIndex = 0; nIndex < routerAddresses.GetSize(); nIndex++)
			{
				sValue = (CString) routerAddresses[nIndex].m_IPAddress;
				if (ContactLocalHost(sValue))
				{
					rc = configManager.SetParameter(eCONFIG_ROUTER_IN_USE, sValue);
					break;
				}
			}
		}
	}
	else
	{
		rc = configManager.SetParameter(eCONFIG_ROUTER_IN_USE, sValue);
	}

	if (rc == RC_SUCCESS)
	{
		LOGDBGSB(CLogger::eLOG_NETMGR, "CNetworkManager::SetActiveNetworkRouterInUse(): Default router installed.  IP address = "_LS_"\n", (LPCXSTR) sValue);
	}
	else
	{
		LOGERRSB(CLogger::eLOG_NETMGR, "CNetworkManager::SetActiveNetworkRouterInUse(): Unable to set router in use.\n");
	}

	return rc;
}

//////////////////////////////////////////////////////////////////////////

int CNetworkManager::ExecSysCmd(const char* sIp, char* sysOutput, int sysOutput_size)
{
#if ! defined(PLATFORM_WINDOWS)
        FILE *fp= 0;
        char output[1024];
	int ret_val = 0;
	if (!sIp){
		LOGERRSB(CLogger::eLOG_NETMGR, "Error ExecSysCmd: received null command\n");
		return ret_val;
	}
	memset (output, '\0', sizeof(output));
	/* Open the command for reading. */
	fp = popen(sIp, "r");
        if (!fp){
		LOGERRSB(CLogger::eLOG_NETMGR, "Error ExecSysCmd: Unable to popen command %s.\n", sIp);
		return ret_val;
        }
	/* Read the output */
	if ( fgets(output, sizeof(output), fp)!= NULL ){
		if (!sysOutput || sysOutput_size <= 0){
			LOGERRSB(CLogger::eLOG_NETMGR, "Error ExecSysCmd: received null output buffer\n");
		}
		else{
			memcpy(sysOutput, output, sysOutput_size);
			ret_val=1;
		}
	}
	int pclose_ret = pclose(fp);
	if (!pclose_ret)
		LOGERRSB(CLogger::eLOG_NETMGR, "Error ExecSysCmd: Unable to pclose. error = %d, errno = %s\n", pclose_ret, strerror(errno));
	return ret_val;
//windows build
#else
	return 0;
#endif
}

//////////////////////////////////////////////////////////////////////////

#if defined(PLATFORM_ANDROID)
THREADSIGNATURE CNetworkManager::VlanTestTimerThread(THREADFNARG arg)
{
	CNetworkManager* pThis = (CNetworkManager*)arg; 
	pThis->DhcpVlanTest();
	return (THREADRETURN) 0;
}
#endif

#if defined (PLATFORM_VXWORKS)
bool CNetworkManager::AddHostFilter(CString sHostIpAddr)
{
	CSyncAutoLock autoLock(m_Lock);

	if (m_pPacketFilter == 0)
	{
		return false;
	}

	CIPAddress ipAddr(sHostIpAddr);
	if (ipAddr.GetAddressInt() == INADDR_NONE)
	{
		LOGERRSB(CLogger::eLOG_NETMGR, "Invalid Host IP Address, "_LS_".\n", (LPCXSTR)sHostIpAddr);
		return false;
	}

	// set a rule to block incoming packets from the host
	CFilterRule rule;
	rule.m_srcAddress.ulAddress = ipAddr.GetAddressInt();
	rule.m_dstAddress.ulAddress = INADDR_ANY;
	rule.m_eAction = eFILTER_DROP;
	rule.m_eDirection = eFILTER_RECEIVE;
	rule.m_protocol.eProto = eFILTER_IP;
	rule.m_sName = TXT("Rx block ") + sHostIpAddr;
	if (!m_pPacketFilter->AddRule(rule))
	{
		return false;
	}

	// set a rule to block outgoing packets to the host
	rule.m_srcAddress.ulAddress = INADDR_ANY;
	rule.m_dstAddress.ulAddress = ipAddr.GetAddressInt();
	rule.m_eDirection = eFILTER_TRANSMIT;
	rule.m_sName = TXT("Tx block ") + sHostIpAddr;
	if (!m_pPacketFilter->AddRule(rule))
	{
		return false;
	}

	return true;
}

bool CNetworkManager::RemoveHostFilter(CString sHostIpAddr)
{
	CSyncAutoLock autoLock(m_Lock);

	if (m_pPacketFilter == 0)
	{
		return false;
	}

	m_pPacketFilter->RemoveRuleByName(TXT("Rx block ") + sHostIpAddr);
	m_pPacketFilter->RemoveRuleByName(TXT("Tx block ") + sHostIpAddr);

	return true;
}

// Debug routines to be used from command line only
// Used to temporarily block IP packets to/from a Host
void BlockHost(char *sbHostIpAddr)
{
	if (!CNetworkManager::Instance().AddHostFilter(UTF8ToUnicode(sbHostIpAddr)))
	{
		printf("Error attempting to block packets to/from Host, %s\n", sbHostIpAddr);
	}
}
void UnblockHost(char *sbHostIpAddr)
{
	if (!CNetworkManager::Instance().RemoveHostFilter(UTF8ToUnicode(sbHostIpAddr)))
	{
		printf("Error attempting to un-block all packets to/from Host, %s\n", sbHostIpAddr);
	}
}

// Debug routines to simulate a Host going down for nDownTime secs 
// and then staying up for nUpTime secs, repeatedly
bool bEndUpDownTask = false;
void tUpDown(char *sbHostIpAddr, int nUpTime, int nDownTime)
{
	if (nUpTime < 1 || nDownTime < 1)
	{
		printf("Up and Down times must each be at least 1 second.\n");
		return;
	}

	printf("Simulating an intermitent connection to host %s\n", sbHostIpAddr);

	unsigned int nTimer = 0;
	bool bToggle = false;  // false indicates "go down"

	// toggle between up and down
	while (!bEndUpDownTask)
	{
		if (nTimer == 0)
		{
			if (!bToggle)
			{
				// block the host at the "go down" time
				BlockHost(sbHostIpAddr);
				printf("  Down: %d secs\n", nDownTime);

				// set timer to "come up" after "down time" expires
				nTimer = nDownTime;
				bToggle = true;
			}
			else
			{
				// unblock the host at the "come up" time
				UnblockHost(sbHostIpAddr);
				printf("  Up: %d secs\n", nUpTime);

				// set timer to "go down" after "up time" expires
				nTimer = nUpTime;
				bToggle = false;
			}
		}

		// wait 1 second
		taskDelay(sysClkRateGet());
		nTimer--;
	}

	// Remove any blocks left active
	UnblockHost(sbHostIpAddr);
}
void StartUpDown(char *sbHostIpAddr, int nUpTime, int nDownTime)
{
	bEndUpDownTask = false;
	taskSpawn("tUpDown", 200, 0, 5000, (FUNCPTR)tUpDown, (int)sbHostIpAddr, nUpTime, nDownTime, 0,0,0,0,0,0,0);
}
void StopUpDown()
{
	bEndUpDownTask = true;
}
#endif /* defined (PLATFORM_VXWORKS) */

//////////////////////////////////////////////////////////////////////////

void CNetworkManager::ProcessNetworkStatusRequest(Msg::CNetworkStatusRequest* pRequest)
{
	LOGDBGSB(CLogger::eLOG_NETMGR, "ProcessNetworkStatusRequest()\n");
	CNetworkStatusResponse response;
	response.m_nClientId = pRequest->m_nClientId;
	response.m_nRequestId = pRequest->m_nRequestId;
	if (m_SecurityMgrNetworkStatusInfo.m_sType != NULL)
	{
		response.m_NetworkStatusInfo.Add(m_SecurityMgrNetworkStatusInfo);
	}
	else
	{
		LOGDBGH(CLogger::eLOG_NETMGR, TXT("ProcessNetworkStatusRequest no SCEP related message received\n"));
	}
	if (m_NetworkMgrNetworkStatusInfo.m_sType != NULL)
	{
		response.m_NetworkStatusInfo.Add(m_NetworkMgrNetworkStatusInfo);
	}

	if (m_SecurityMgrLoadCertInfo.m_sType != NULL)
	{
		response.m_NetworkStatusInfo.Add(m_SecurityMgrLoadCertInfo);
	}
	if (m_SecurityMgrTrustCertInfo.m_sType != NULL)
	{
		response.m_NetworkStatusInfo.Add(m_SecurityMgrTrustCertInfo);
	}
	if (m_SecurityMgrMyCertInfo.m_sType != NULL)
	{
		response.m_NetworkStatusInfo.Add(m_SecurityMgrMyCertInfo);
	}
	SendResponse(&response, pRequest);

}
//////////////////////////////////////////////////////////////////////////

void CNetworkManager::ProcessWiFiConnectNetworkRequest(Msg::CWifiConnectNetworkRequest* pRequest)
{
	if ((m_pNetAdaptor != NULL) && (pRequest != NULL))
	{
		CWifiConnectNetworkResponse response;

		response.m_nResult = m_pNetAdaptor->ConnectNetwork(pRequest->m_sSsid, pRequest->m_Credentials);
		SendResponse(&response, pRequest);
	}
}

//////////////////////////////////////////////////////////////////////////

void CNetworkManager::StoreLastSentNetEvent(const XCHAR* pType, const XCHAR* pData)
{
	LOGDBGH(CLogger::eLOG_NETMGR, TXT("StoreLastSentNetEvent Msg. Type = %ls , Data = %ls\n"), pType, pData);
	m_NetworkMgrNetworkStatusInfo.m_sType = pType;
	m_NetworkMgrNetworkStatusInfo.m_sData = pData;
}

//////////////////////////////////////////////////////////////////////////

bool CNetworkManager::LoadIPv6Module()
{
	if (m_pNetAdaptor != NULL)
	{
		return m_pNetAdaptor->LoadIPv6Module();
	}
	else
	{
		LOGERRSB(CLogger::eLOG_NETMGR, "ERROR: cannot load IPv6 module. Reason: Net Adaptor is not available.\n");
		return false;
	}
}

//////////////////////////////////////////////////////////////////////////

bool CNetworkManager::IsIPv6Enabled()
{
	if (m_pNetAdaptor != NULL)
	{
		return m_pNetAdaptor->IsIPv6Enabled();
	}
	else
	{
		LOGERRSB(CLogger::eLOG_NETMGR, "ERROR: cannot check IPv6 status. Reason: Net Adaptor is not available.\n");
		return false;
	}
}



//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// Begin IWiFiObserver responsibilities
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////

void CNetworkManager::WiFiEventServiceStatusCallback(const etWIFI_SERVICE_STATUS eStatus)
{
	LOGDBGSB(CLogger::eLOG_NETMGR, "CNetworkManager::WiFiEventServiceStatusCallback(status=%ls)\n",
									(PCXSTR)GetWifiServiceStatusNameFromType(eStatus));

	CWifiServiceStatusEvent serviceStatusEvent;
	serviceStatusEvent.m_eStatus = eStatus;
	CCoreMsgManager::Instance().PutMessage(&serviceStatusEvent);

	// WIFITBD Complete this code when all status defs are available
	switch (eStatus)
	{
		case eWIFI_SERVICE_STATUS_STOPPED:
			break;
		case eWIFI_SERVICE_STATUS_STARTING:
			break;
		case eWIFI_SERVICE_STATUS_STARTED:
			SendNetEvent(NET_MSG_WIFI_SERVICE_START_SUCCESS);
			break;
		case eWIFI_SERVICE_STATUS_STOPPING:
			break;
		case eWIFI_SERVICE_STATUS_FAILED:
			SendNetEvent(NET_MSG_WIFI_SERVICE_START_FAIL);	
			break;
		default:
			break;
	}
}

//////////////////////////////////////////////////////////////////////////

void CNetworkManager::WiFiEventConnectionStatusCallback(const etWIFI_CONNECTION_STATUS eStatus)
{
	CWifiConnectionStatusEvent connectionStatusEvent;
	connectionStatusEvent.m_eStatus = eStatus;
	CCoreMsgManager::Instance().PutMessage(&connectionStatusEvent);

	LOGDBGSB(CLogger::eLOG_NETMGR, "CNetworkManager::WiFiEventConnectionStatusCallback(status=%ls)\n",
									(PCXSTR)GetWifiConnectionStatusNameFromType(eStatus));

	switch (eStatus)
	{
		case eWIFI_CONNECTION_STATUS_AUTHENTICATING:
			SendNetEvent(NET_MSG_WIFI_STATUS_AUTHENTICATING);
			break;

		case eWIFI_CONNECTION_STATUS_AUTHENTICATION_FAILED:
			SendNetEvent(NET_MSG_WIFI_STATUS_AUTH_FAILED);
			break;

		case eWIFI_CONNECTION_STATUS_CONNECTED:
			SendNetEvent(NET_MSG_WIFI_STATUS_CONNECTED);
			break;

		case eWIFI_CONNECTION_STATUS_CONNECTING:
			SendNetEvent(NET_MSG_WIFI_STATUS_CONNECTING);
			break;

		case eWIFI_CONNECTION_STATUS_DISCONNECTED:
			SendNetEvent(NET_MSG_WIFI_STATUS_DISCONNECTED);
			break;

		case eWIFI_CONNECTION_STATUS_FAILED:
			SendNetEvent(NET_MSG_WIFI_STATUS_FAILED);
			break;

		case eWIFI_CONNECTION_STATUS_NETWORK_NOT_FOUND:
			SendNetEvent(NET_MSG_WIFI_STATUS_NETWORK_NOT_FOUND);
			break;

		default:
			LOGERRSB(CLogger::eLOG_NETMGR, "CNetworkManager::WiFiEventConnectionStatusCallback: Unrecognized status=%d", eStatus);
			break;
	}
}

//////////////////////////////////////////////////////////////////////////

void CNetworkManager::WiFiEventScanStatusCallback(const bool bScanning)
{
	LOGDBGSB(CLogger::eLOG_NETMGR, "CNetworkManager::WiFiEventScanStatusCallback(bScanning=%s)\n",
									(bScanning ? "true" : "false"));

	CWifiScanStatusEvent scanStatusEvent;
	scanStatusEvent.m_bScanning = bScanning;
	CCoreMsgManager::Instance().PutMessage(&scanStatusEvent);
}

//////////////////////////////////////////////////////////////////////////

void CNetworkManager::WiFiEventRssiUpdatedCallback(const unsigned int nBars)
{
	LOGDBGSB(CLogger::eLOG_NETMGR, "CNetworkManager::WiFiEventRssiUpdatedCallback(numBars=%d)\n", nBars);

	CWifiRssiUpdatedEvent rssiUpdatedEvent;
	rssiUpdatedEvent.m_nNumRssiBars = nBars;
	CCoreMsgManager::Instance().PutMessage(&rssiUpdatedEvent);
}

//////////////////////////////////////////////////////////////////////////

void CNetworkManager::WiFiEventNetworkListUpdatedCallback(const CWifiNetworkList* pList)
{
	LOGDBGSB(CLogger::eLOG_NETMGR, "CNetworkManager::WiFiEventNetworkListUpdatedCallback()\n");

	CWifiNetworkListUpdatedEvent networkListUpdatedEvent;
	networkListUpdatedEvent.m_NetworkList = *pList;
	CCoreMsgManager::Instance().PutMessage(&networkListUpdatedEvent);
}

//////////////////////////////////////////////////////////////////////////

void CNetworkManager::WiFiEventPongCallback(void)
{
	LOGDBGSB(CLogger::eLOG_NETMGR, "CNetworkManager::WiFiEventPongCallback()\n");

	// WIFITBD
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// End IWiFiObserver responsibilities
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

#if defined (FEATURE_WIFI_EMULATION)
THREADSIGNATURE CNetworkManager::NetworkWiFiTestMethod(THREADFNARG arg)
{
	CNetworkManager* pThis = (CNetworkManager*)arg; 
	INetworkAdaptor* m_pWiFiAdaptor;
	CPlatform::DelayThread(10000);

	LOGDBGSB(CLogger::eLOG_NETMGR, "[MMM ==== NetworkWiFiTestMethod] start thread\n");
	m_pWiFiAdaptor = SPARK_NEW(eMEM_MGR) CUnixWiFiNetworkAdaptor(pThis);
	LOGDBGSB(CLogger::eLOG_NETMGR, "[MMM ==== NetworkWiFiTestMethod] WiFiAdaptor Initialize \n");
	m_pWiFiAdaptor->Initialize();

	CPlatform::DelayThread(30000);
	LOGDBGSB(CLogger::eLOG_NETMGR, "[MMM ==== NetworkWiFiTestMethod] WiFi_NetworkScan start \n");
	WiFi_NetworkScan();

	CPlatform::DelayThread(30000);
	CString sSSID;
	CWifiCredentials credentials;
	LOGDBGSB(CLogger::eLOG_NETMGR, "[MMM ==== NetworkWiFiTestMethod] ConnectNetwork \n");
	if(m_pWiFiAdaptor->ConnectNetwork(sSSID, credentials) == 0)
	{
		LOGDBGSB(CLogger::eLOG_NETMGR, "[MMM ==== NetworkWiFiTestMethod] ConnectNetwork success\n");
	}
	else
	{
		LOGDBGSB(CLogger::eLOG_NETMGR, "[MMM ==== NetworkWiFiTestMethod] ConnectNetwork failed\n");
	}

	CPlatform::DelayThread(30000);
	LOGDBGSB(CLogger::eLOG_NETMGR, "[MMM ==== NetworkWiFiTestMethod] WiFi_StopService start \n");
	WiFi_StopService();

	CPlatform::DelayThread(300000);
	LOGDBGSB(CLogger::eLOG_NETMGR, "[MMM ==== NetworkWiFiTestMethod] WiFiAdaptor Delete \n");
	SPARK_DELETE(m_pWiFiAdaptor, eMEM_MGR);

	return (THREADRETURN) 0;
}
#endif // FEATURE_WIFI_EMULATION


//////////////////////////////////////////////////////////////////////////

void CNetworkManager::Trigger8021xLogoffRequest()
{
	LOGDBGHSB(CLogger::eLOG_NETMGR, "CNetworkManager::Trigger8021xLogoffRequest().\n");
	
	if (IsActiveNetworkEthernet())
	{
		CDot1xLogoffRequest xRequest;
		CCoreMsgManager::Instance().PutMessage(&xRequest);
		
		m_8021xLogoffSuccess.Reset();
	}
}

THREADSIGNATURE CNetworkManager::PhoneReportThread(THREADFNARG arg)
{
	CSendPhoneReportResponse response;
	int nResponseCode = 0;
	response.m_nStatusCode = RC_FAILED;
	CSendPhoneReportRequest* pRequest = static_cast<CSendPhoneReportRequest*>(arg);
#if defined(IPPCFG_DVF99)

	//generate report file if needed
	if (!pRequest->m_bIsOldReport)
	{
		system(PHONE_REPORT_CMD);
	}

	//check if report file exists
	if (!CFile::Exists(g_sReportFileName))
	{
		LOGERRSB(CLogger::eLOG_NETMGR, "CNetworkManager::PhoneReportThread report file doesn't exist\n");
		CCoreMsgManager::Instance().PutMessage(&response);
		SPARK_DELETE(pRequest, eMEM_MGR);
		return (THREADRETURN)-1;
	}

	//now we have a report file in flash at least
	response.m_nStatusCode = RC_SUCCESS;

	CConfigurationManager& configManager = CConfigurationManager::Instance();

	CString sURI = configManager.GetStringParameter(eCONFIG_REPORT_SERVER_URI);
	CString sUserID = configManager.GetStringParameter(eCONFIG_SIP_USER_ID);

	if (!sURI.IsEmpty() && !sUserID.IsEmpty())
	{
		CFile file;
		if (file.Open(g_sReportFileName,eFILE_READ) != NULL)
		{
			LOGERRSB(CLogger::eLOG_NETMGR, "CNetworkManager::PhoneReportThread report file cannot be opened\n");
			CCoreMsgManager::Instance().PutMessage(&response);
			SPARK_DELETE(pRequest, eMEM_MGR);
			return (THREADRETURN)-1;
		}
		
		CHTTPRequest httpRequest;
		CHTTPResponse httpResponse;

		IBaseHTTPInterface* pHttpInterface = CHTTPFactory::Create();
		
		//for consistency set the same timeouts as 96x1 H323
		pHttpInterface->SetTransferTimeout(REPORT_HTTP_TRANSFER_TIMEOUT);
		pHttpInterface->SetConnectionTimeout(REPORT_HTTP_CONNECTION_TIMEOUT);

		if (!pRequest->m_sUsername.IsEmpty() && !pRequest->m_sPassword.IsEmpty())
		{
			pHttpInterface->SetAuthInfo(pRequest->m_sUsername, pRequest->m_sPassword);
		}

		httpRequest.m_sAction = TXT("PUT");
		httpRequest.m_pUploadFile = file.GetStream();
		httpRequest.m_bSaveAsRawData = true;

		if (!sURI.EndsWith(TXT("/")))
		{
			sURI.Append(TXT("/"));
		}

		//set report file name
		sURI.Append(sUserID + TXT("_report.tgz"));

		//special parsing for BRURI is not needed, curl handles all the different URI formats just fine
		etHTTP_RETURN_CODE eHttpResponse = pHttpInterface->FetchURL(sURI, httpRequest, httpResponse);

		nResponseCode = httpResponse.GetResponseCode();
		LOGDBGHSB(CLogger::eLOG_NETMGR, "CNetworkManager::PhoneReportThread, FetchURL returned: %d with code: %d\n", eHttpResponse, nResponseCode);

		response.m_nResponseCode = nResponseCode;

		if (nResponseCode == HTTP_RESPONSE_401_UNAUTHORIZED)
		{
			//extract realm from header, it should be like: Basic realm="myrealm"
			CString sRealm;
			httpResponse.m_Headers.GetHeader(TXT("WWW-Authenticate"),sRealm);
			response.m_sRealm = sRealm.ExtractData(TXT('"'),TXT('"'));
		}

		file.Close();
		CHTTPFactory::Delete(pHttpInterface);
	}
#endif
	CCoreMsgManager::Instance().PutMessage(&response);
	SPARK_DELETE(pRequest, eMEM_MGR);
	return NULL;
}

//////////////////////////////////////////////////////////////////////////

void CNetworkManager::ProcessPhoneReportRequest(CSendPhoneReportRequest* pRequest)
{
	LOGDBGHSB(CLogger::eLOG_NETMGR, "CNetworkManager::ProcessPhoneReportRequest\n");

	if (!m_PhoneReportThread.IsRunning())
	{
		m_PhoneReportThread.Start(CString(TXT("tReportThread")), (THREADFNPTR)PhoneReportThread, (THREADFNARG)pRequest->Clone(), eTHREAD_PRIORITY_BACKGROUND);
	}
	else
	{
		CSendPhoneReportResponse response;
		response.m_nStatusCode = RC_FAILED;
		CCoreMsgManager::Instance().PutMessage(&response);
	}
}

