import pyshark

count = 0
def packetHandler(pkt):
    global count
    try:
        print("Novo pacote", count)
        count = count + 1
#        if "wlan_mgt" in pkt:
#            nossid = False
#            if not str(pkt.wlan_mgt.tag)[:34] == "Tag: SSID parameter set: Broadcast":
#                ssid = pkt.wlan_mgt.ssid
#            else:
#               nossid = True
#        else:
#            nossid = False
#            if not str(pkt[3].tag)[:34] == "Tag: SSID parameter set: Broadcast":
#                ssid = pkt[3].ssid
#            else:
#                nossid = True

        rssi_val = pkt.radiotap.dbm_antsignal
        mac_address = pkt.wlan.ta
        bssid = pkt.wlan.da
        print("-------------------------------- PACOTE")
        print(rssi_val, mac_address, bssid)
        print("---------------------------------------")
    except:
        print("tou aqui")
        print("parei")



capture = pyshark.LiveCapture(interface="wlp2s0mon", bpf_filter='type mgt subtype probe-req')
capture.apply_on_packets(packetHandler)
