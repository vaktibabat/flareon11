import threading

def GenerateFlagText(x, y):
    key = x + y*20
    encoded = "\xa5\xb7\xbe\xb1\xbd\xbf\xb7\x8d\xa6\xbd\x8d\xe3\xe3\x92\xb4\xbe\xb3\xa0\xb7\xff\xbd\xbc\xfc\xb1\xbd\xbf"
    return ''.join([chr(ord(c) ^ key) for c in encoded])

tasks = []
tasks_lock = threading.Lock()

for x, y in zip(range(100000), range(10000)):
    tasks.append((x, y))

def thread_func():
    while True:
        with tasks_lock:
	        if len(tasks) > 0:
	            x, y = tasks.pop()
	
	            if "flare" in GenerateFlagText(x, y):
	                print(GenerateFlagText(x, y))
	                break
	        else:
		        return

threads = []

for _ in range(100):
    threads.append(threading.Thread(target=thread_func))

for t in threads:
    t.start()

for t in threads:
    t.join()

# Output: welcome_to_11@flare-on.com
