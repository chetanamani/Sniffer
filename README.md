# Sniffer
This project aims to build a lightweight yet effective real-time packet sniffer 
that not only captures and logs network traffic but also detects and alerts against suspicious activity using Python and open-source libraries.
      Here i used the following libraries and tools like
          Scapy  -  for real time packet capture
          SQLite  -  for storing the packet metadata
          matplotlib  -  for system alert logs and visualize live track trends
          Python 3   -  for core programming language
          kali linux  -  Development and Testing environment
Here the main components or code are divided in to five parts like 
  capturing the live tcp/ip address , manages the SQLite database operations ,detecting suspicious packet patterns ,Logs alerts to a file if a threat is detected ,Visualizes live traffic rate.

Steps for building project environment:
1.Environment setup:
  => Installed Python libraries: scapy, sqlite3, and matplotlib.
  => Created a structured folder for storing scripts and logs.
    
2.Packet capture:    
    => Sniffer.py - Captures live TCP/IP packets and forwards data to storage and detection modules.
                  Used scapy.sniff() to capture TCP packets in real-time.
   import sqlite3
from datetime import datetime

def init_db():
    conn = sqlite3.connect('packets.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS packets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        src_ip TEXT,
        dst_ip TEXT,
        src_port INTEGER,
        dst_port INTEGER,
        length INTEGER,
        flags TEXT
    )''')
    conn.commit()
    conn.close()

def insert_packet(src_ip, dst_ip, src_port, dst_port, length, flags):
    conn = sqlite3.connect('packets.db')
    c = conn.cursor()
    c.execute("INSERT INTO packets (timestamp, src_ip, dst_ip, src_port, dst_port, length, flags) VALUES (?, ?, ?, ?, ?, ?, ?)", 
              (datetime.now(), src_ip, dst_ip, src_port, dst_port, length, flags))
    conn.commit()
    conn.close()

3.Database logging:
     => db_handler.py - Stored packets in a local SQLite database (packets.db) for review and graph plotting.
  import sqlite3
from datetime import datetime

def init_db():
    conn = sqlite3.connect('packets.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS packets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        src_ip TEXT,
        dst_ip TEXT,
        src_port INTEGER,
        dst_port INTEGER,
        length INTEGER,
        flags TEXT
    )''')
    conn.commit()
    conn.close()

def insert_packet(src_ip, dst_ip, src_port, dst_port, length, flags):
    conn = sqlite3.connect('packets.db')
    c = conn.cursor()
    c.execute("INSERT INTO packets (timestamp, src_ip, dst_ip, src_port, dst_port, length, flags) VALUES (?, ?, ?, ?, ?, ?, ?)", 
              (datetime.now(), src_ip, dst_ip, src_port, dst_port, length, flags))
    conn.commit()
    conn.close()

4.Anomoly Detection:
     => Anomaly_detector.py - Monitored number of requests per IP within a 10-second sliding window.
from collections import defaultdict
import time

connection_tracker = defaultdict(list)
THRESHOLD = 20  # connections per IP per 10 sec

def detect_anomaly(src_ip, dst_port):
    current_time = time.time()
    connection_tracker[src_ip].append(current_time)
    # Remove old entries
    connection_tracker[src_ip] = [t for t in connection_tracker[src_ip] if current_time - t < 10]
    
  if len(connection_tracker[src_ip]) > THRESHOLD:
        return True
    return False   

5.Alert System:
    => alert.py - Detected anomalies are written to alerts.log.
    
  def send_alert(src_ip):
    with open("alerts.log", "a") as f:
        f.write(f"[!] ALERT: Suspicious activity from {src_ip}\n")

6.Live Plotting:
      => plotting.py - Used matplotlib.animation to plot packet rate over time.

  import sqlite3
import matplotlib.pyplot as plt
import matplotlib.animation as animation
from datetime import datetime

# Set up figure
fig, ax = plt.subplots()
x_data, y_data = [], []
line, = ax.plot_date(x_data, y_data, '-')

def fetch_packet_counts():
    conn = sqlite3.connect('packets.db')
    cursor = conn.cursor()
    cursor.execute("SELECT strftime('%H:%M:%S', timestamp), COUNT(*) FROM packets GROUP BY strftime('%H:%M:%S', timestamp) ORDER BY timestamp DESC LIMIT 20")
    results = cursor.fetchall()
    conn.close()
    return results[::-1]  # oldest to newest

def update(frame):
    results = fetch_packet_counts()
    if results:
        times, counts = zip(*results)
        x_data.clear()
        y_data.clear()
        x_data.extend([datetime.strptime(t, '%H:%M:%S') for t in times])
        y_data.extend(counts)

   line.set_data(x_data, y_data)
        ax.relim()
        ax.autoscale_view()

  return line,

ani = animation.FuncAnimation(fig, update, interval=1000)
plt.title("Live Packet Count (per second)")
plt.xlabel("Time")
plt.ylabel("Packet Count")
plt.tight_layout()
plt.show()

7. Conclusion
    => This project successfully demonstrates a compact network monitoring and anomaly detection system built entirely using Python.
       It introduces key cybersecurity concepts such as intrusion detection, traffic logging, and packet analysis.
       Its modular structure allows for future enhancements, such as protocol filtering, email alerts, and a GUI dashboard.
       
