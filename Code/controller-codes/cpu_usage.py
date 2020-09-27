# run on terminal "python monitor.py pid_of_controller"
import psutil 
import time 
import sys  
#get pid of running ryu-manager  
pid = psutil.Process(int(sys.argv[1]))
	 
while True: 	
    cpu = pid.cpu_percent()
    monitor = open("monitor.txt", "a+")
    monitor.write(str(cpu) + "\n")
    time.sleep(1)
monitor.close()

