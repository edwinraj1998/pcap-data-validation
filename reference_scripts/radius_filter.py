import os
import pyshark
import pandas as pd

def extract_radius_data(pcap_file, output_excel):
    """Extract RADIUS packets from a PCAP file and provide network intelligence."""
    print(f"🔍 Processing: {pcap_file}")

    data = []  # List to store extracted data for DataFrame creation

    try:
        capture = pyshark.FileCapture(pcap_file, display_filter="radius")

        for packet in capture:
            try:
                # Extract Ethernet layer MAC addresses
                src_mac = packet.eth.src if 'eth' in packet else "N/A"
                dst_mac = packet.eth.dst if 'eth' in packet else "N/A"

                # Extract IP layer and RADIUS details
                src_ip = packet.ip.src if 'ip' in packet else "N/A"
                dst_ip = packet.ip.dst if 'ip' in packet else "N/A"
                radius_code = packet.radius.code  
                username = packet.radius.get("User_Name", "N/A")  # Safe retrieval
                called_station_id = packet.radius.get("Called_Station_Id", "N/A")
                calling_station_id = packet.radius.get("Calling_Station_Id", "N/A")
                nas_ip_address = packet.radius.get("NAS_IP_Address", "N/A")
                framed_ip_address = packet.radius.get("Framed_IP_Address", "N/A")
                auth_method = packet.radius.get("NAS_Port_Type", "N/A")  # This can tell us if it's wired or wireless
                acct_session_time = packet.radius.get("Acct-Session-Time", "N/A")
                called_station_id = packet.radius.get("Called_Station_Id", "N/A")
                connect_time = packet.sniff_time.isoformat()  # Timestamp of packet capture (may need adjustment)
                
                # Detect WiFi vs Mobile users based on username pattern
                if "@wlan." in username:
                    connection_type = "WiFi"
                elif "@mobile" in username:
                    connection_type = "Mobile"
                else:
                    connection_type = "Unknown"
                
                # Handle RADIUS Codes for access accept/reject
                auth_status = "Success" if radius_code == "2" else "Failure"  # 2 is the code for Access-Accept

                # Append the data to the list for DataFrame creation
                data.append([packet.number, src_mac, dst_mac, src_ip, dst_ip, radius_code, username, 
                             called_station_id, calling_station_id, nas_ip_address, framed_ip_address, 
                             connection_type, auth_status, auth_method, acct_session_time, connect_time])

            except AttributeError:
                continue  # Skip packets without required fields

        capture.close()

        # Create a DataFrame and export to Excel
        df = pd.DataFrame(data, columns=[
            "Packet Number", "Source MAC", "Destination MAC", "Source IP", "Destination IP", 
            "RADIUS Code", "Username", "Called Station ID", "Calling Station ID", 
            "NAS IP Address", "Framed IP Address", "Connection Type", "Authentication Status", 
            "Authentication Method", "Session Time", "Connection Time"
        ])

        # Save the DataFrame to an Excel file
        df.to_excel(output_excel, index=False)
        print(f"✅ Extracted data saved to: {output_excel}")

    except Exception as e:
        print(f"❌ Error processing {pcap_file}: {e}")

def process_all_pcaps(pcap_folder, output_folder):
    """Process all PCAP files in a folder and export to Excel."""
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    for file in os.listdir(pcap_folder):
        if file.endswith(".pcap"):
            pcap_file = os.path.join(pcap_folder, file)
            output_excel = os.path.join(output_folder, f"{file}.xlsx")
            extract_radius_data(pcap_file, output_excel)

if __name__ == "__main__":
    pcap_folder = r"\\172.50.32.26\d$\Edwin\TvaraaDumpData"
    output_folder = r"C:\Users\edwin.rajan\CascadeProjects\python_scripts\radius"

    print(f"🚀 Starting RADIUS extraction for PCAPs in: {pcap_folder}")
    process_all_pcaps(pcap_folder, output_folder)
    print("🎯 All PCAPs processed successfully!")
