import re
import csv
import argparse

Default_threhold = 10

def Task1_parsing(file_path):
    '''Task1.1 - Parsing the provided log file to extract all IP addresses.'''
    with open(file_path, 'r') as file:
        logs = file.readlines()
    return logs

def Task1_counting_requests_per_ip(logs):
    '''Task 1.2 - Calculating the number of requests made by each IP address.'''
    ip_count = {}

    for log in logs:
        ip_address = log.split()[0]
        if ip_address in ip_count:
            ip_count[ip_address] += 1
        else:
            ip_count[ip_address] = 1

    return ip_count


def Task2_most_accessed_endpoint(logs):
    '''Task 2 - Identifying the most frequently accessed endpoint'''

    endpoint_count = {}
    for log in logs:
        match = re.search(r'\"(GET|POST) (.+?) ', log)
        if match:
            endpoint = match.group(2)
            if endpoint not in endpoint_count:
                endpoint_count[endpoint] = 0
            endpoint_count[endpoint] += 1
    most_accessed = None
    max_count = 0
    for endpoint, count in endpoint_count.items():
        if count > max_count:
            max_count = count
            most_accessed = (endpoint, count)
    return most_accessed, endpoint_count


def Task3_detecting_suspicious_activity(logs, Default_threhold=10):
    '''Task 3 - Detect suspicious activity'''
    failed_login_count = {}
    for log in logs:
        if "401" in log or "Invalid credentials" in log:
            ip_address = log.split()[0]
            if ip_address in failed_login_count:
                failed_login_count[ip_address] += 1
            else:
                failed_login_count[ip_address] = 1
    suspicious_ips = {}
    for ip, count in failed_login_count.items():
        if count > Default_threhold:
            suspicious_ips[ip] = count
    return suspicious_ips

def Task4_SavingResults(ip_counts, most_accessed, suspicious_ips, endpoint_count, result_file):
    '''Task 4 - Saving results to cvs named log_analysis_results.csv'''
    with open(result_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        
        writer.writerow(['IP Address', 'Request Count'])

        #Task1.3 Sort and display the results in descending order of request counts.'''
        for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True):
            writer.writerow([ip, count])
        writer.writerow([])

    
        writer.writerow(['Most Accessed Endpoint', 'Access Count'])
        writer.writerow([most_accessed[0], most_accessed[1]])
        writer.writerow([])

        
        writer.writerow(['IP Address', 'Failed Login Attempts'])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])
        writer.writerow([])

        writer.writerow(['Endpoint', 'Access Count'])
        def sort_by_count(item):
            return item[1] 
        sorted_endpoint_counts = sorted(endpoint_count.items(), key=sort_by_count, reverse=True)
        for endpoint, count in sorted_endpoint_counts:
            writer.writerow([endpoint, count])
        

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('Logfile', type=str)
    parser.add_argument('--Top_ips', type=int)
    parser.add_argument('--Top_endpoints', type=int)
    parser.add_argument('--result_file', type=str, default='log_analysis_results.csv')
    
    args = parser.parse_args()
    logs = Task1_parsing(args.Logfile)
    
    ip_counts = Task1_counting_requests_per_ip(logs)
    most_accessed, endpoint_count = Task2_most_accessed_endpoint(logs)
    suspicious_ips = Task3_detecting_suspicious_activity(logs)
    print("IP Address Request Count")
    
   
    for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:args.Top_ips]:
        print(f"{ip:<20} {count}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")

    print("\nSuspicious Activity Detected:")
    print("IP Address Failed Login Attempts")
    
    for ip, count in suspicious_ips.items():
        print(f"{ip:<20} {count}")
    print("\nTop Endpoints Accessed:")
    print("Endpoint Access Count")

    for endpoint, count in sorted(endpoint_count.items(), key=lambda x: x[1], reverse=True)[:args.Top_endpoints]:
        print(f"{endpoint:<20} {count}")

    Task4_SavingResults(ip_counts, most_accessed, suspicious_ips, endpoint_count, args.result_file)
    print(f"\nResults saved to {args.result_file}")

if __name__ == "__main__":
    main()
