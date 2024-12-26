#include <iostream>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <unordered_set>
#include <fstream>

// Global log file
std::ofstream logFile("network_log.txt", std::ios::out);

// Function to parse and display packet information
void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    // IP header starts after Ethernet header (14 bytes)
    const struct ip *ipHeader = (struct ip *)(packet + 14);
    char srcIp[INET_ADDRSTRLEN], dstIp[INET_ADDRSTRLEN];

    // Convert IP addresses to readable format
    inet_ntop(AF_INET, &(ipHeader->ip_src), srcIp, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ipHeader->ip_dst), dstIp, INET_ADDRSTRLEN);

    std::cout << "Packet captured:\n";
    std::cout << "\tSource IP: " << srcIp << "\n";
    std::cout << "\tDestination IP: " << dstIp << "\n";

    // Log packet information to file
    logFile << "Packet captured:\n";
    logFile << "\tSource IP: " << srcIp << "\n";
    logFile << "\tDestination IP: " << dstIp << "\n";

    // Example: Detect traffic from a suspicious IP (e.g., 192.168.1.100)
    std::unordered_set<std::string> suspiciousIps = {"192.168.1.100", "10.0.0.1"};
    if (suspiciousIps.count(srcIp) > 0 || suspiciousIps.count(dstIp) > 0) {
        std::cout << "\t[ALERT] Suspicious IP detected: " << (suspiciousIps.count(srcIp) > 0 ? srcIp : dstIp) << "\n";
        logFile << "\t[ALERT] Suspicious IP detected: " << (suspiciousIps.count(srcIp) > 0 ? srcIp : dstIp) << "\n";
    }

    std::cout << "-------------------------\n";
    logFile << "-------------------------\n";
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    const char *dev;

    // Open log file
    logFile << "Starting Network Monitoring Log\n";

    // Find a network device to sniff
    dev = pcap_lookupdev(errbuf);
    if (dev == nullptr) {
        std::cerr << "Error finding device: " << errbuf << std::endl;
        logFile << "Error finding device: " << errbuf << std::endl;
        return 1;
    }

    std::cout << "Using device: " << dev << std::endl;
    logFile << "Using device: " << dev << "\n";

    // Open the device for packet capture
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Error opening device: " << errbuf << std::endl;
        logFile << "Error opening device: " << errbuf << std::endl;
        return 1;
    }

    // Set a filter for IP packets (optional)
    struct bpf_program fp;
    const char filterExp[] = "ip";
    if (pcap_compile(handle, &fp, filterExp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "Error setting filter: " << pcap_geterr(handle) << std::endl;
        logFile << "Error setting filter: " << pcap_geterr(handle) << std::endl;
        return 1;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "Error applying filter: " << pcap_geterr(handle) << std::endl;
        logFile << "Error applying filter: " << pcap_geterr(handle) << std::endl;
        return 1;
    }

    std::cout << "Starting packet capture...\n";
    logFile << "Starting packet capture...\n";

    // Capture packets indefinitely
    pcap_loop(handle, 0, packetHandler, nullptr);

    // Cleanup
    pcap_freecode(&fp);
    pcap_close(handle);

    // Close log file
    logFile << "Network Monitoring Ended\n";
    logFile.close();

    return 0;
}
