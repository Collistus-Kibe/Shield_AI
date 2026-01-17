import psutil
import geoip2.database
import os
from ipaddress import ip_address

# Path to the GeoIP database
DB_PATH = os.path.join('data', 'GeoLite2-City.mmdb')
reader = None

# Load the database reader once when the module is imported
try:
    if os.path.exists(DB_PATH):
        reader = geoip2.database.Reader(DB_PATH)
except Exception as e:
    print(f"Could not load GeoIP database: {e}. Location data will not be available.")

def get_geoip_location(ip):
    """Looks up the geographic location of an IP address."""
    if not reader or not ip:
        return "N/A", "N/A"
    
    try:
        # Ignore private/local IP addresses
        if ip_address(ip).is_private or ip_address(ip).is_loopback:
            return "Local", "Private Network"
            
        response = reader.city(ip)
        country = response.country.name or "Unknown"
        city = response.city.name or "Unknown"
        return country, city
    except geoip2.errors.AddressNotFoundError:
        return "Unknown", "N/A"
    except Exception:
        return "Error", "N/A"

def get_active_connections(log):
    """
    Scans for active TCP connections and enriches them with GeoIP data.
    """
    connections = []
    try:
        net_conns = psutil.net_connections(kind='tcp')
        for conn in net_conns:
            if conn.status == 'ESTABLISHED' and conn.raddr:
                proc_name = "?"
                try:
                    p = psutil.Process(conn.pid)
                    proc_name = p.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
                
                remote_ip = conn.raddr.ip
                country, city = get_geoip_location(remote_ip)

                connections.append({
                    'pid': conn.pid or "N/A",
                    'process': proc_name,
                    'remote_addr': f"{remote_ip}:{conn.raddr.port}",
                    'country': country,
                    'city': city
                })
    except Exception as e:
        log.error(f"NETWORK_MONITOR: Failed to retrieve connections. Reason: {e}")

    return connections