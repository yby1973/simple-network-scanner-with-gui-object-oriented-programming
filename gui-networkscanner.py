from tkinter import Tk, Button, Label, Entry, Listbox, scrolledtext, END
import os
import threading


class returnedVariables(object):
    def __init__(self):
        self.scanned_addrsses = []
        self.finished = False

    def returnedVariable(self, x):
        self.scanned_addrsses.append(x)

    def finish(self):
        self.finished = True

    def clear_addresses(self):
        self.scanned_addrsses = []


returned_variable_class = returnedVariables()


class Functions(object):
    lock = threading.Lock()

    def get_ip_addresses(self):
        addresses = []
        output_lines = os.popen("ipconfig").readlines()
        for line in output_lines:
            if "IPv4 Address" in line:
                ip = line[line.find(":")+2:-1]
                addresses.append(ip)
        return addresses

    def ping(self, target):
        output = os.popen("ping {0} -n 1".format(target)).read()
        if "TTL" in output:
            with Functions.lock:
                returned_variable_class.returnedVariable(target)

    def scan(self, target):
        network = target[:target.rfind(".")+1]
        for i in range(1, 255):
            target_ip = network + str(i)
            if target_ip == target:
                continue
            self.ping(target_ip)

    def threaded_scan(self, target):
        threads = []
        network = target[:target.rfind(".") + 1]
        for i in range(1, 255):
            target_ip = network + str(i)
            if target_ip == target:
                continue
            pinger = threading.Thread(target=self.ping, args=(target_ip,))
            pinger.start()
            threads.append(pinger)
        else:
            for t in threads:
                t.join()
            returned_variable_class.finish()


class Program(Functions):
    def __init__(self):
        # window configuration
        self.window = Tk()
        self.window.title("Network Scanner")
        self.window.geometry("350x460")
        self.window.iconbitmap("snake.ico")

        ip_addresses = self.get_ip_addresses()

        # items
        title_lbl = Label(self.window, text="Network Scanner", font=("Arial", 15))
        title_lbl.place(x=80, y=5)

        lbl1 = Label(self.window, text="Target:")
        lbl1.place(x=5, y=50)

        self.ent1 = Entry(self.window, width=20)
        self.ent1.place(x=60, y=50)

        btn1 = Button(self.window, text="Scan", width=10, activebackground="grey", command=lambda: self.threaded_writer())
        btn1.place(x=200, y=50)

        lbl2 = Label(self.window, text="IP Addresses on this machine:")
        lbl2.place(x=5, y=100)

        self.lstbox1 = Listbox(self.window, height=4, width=30)
        self.lstbox1.place(x=5, y=125)
        for ip in ip_addresses:
            self.lstbox1.insert(END, ip)

        btn2 = Button(self.window, text="Pick target", activebackground="grey", command=self.pick_target)
        btn2.place(x=5, y=200)

        self.txtbox1 = scrolledtext.ScrolledText(self.window, width=40, height=12)
        self.txtbox1.configure(state="disabled")
        self.txtbox1.place(x=5, y=240)

    def clear_textbox(self):
        self.txtbox1.configure(state="normal")
        self.txtbox1.delete("0.1", END)
        self.txtbox1.configure(state="disabled")

    def write_to_textbox(self):
        self.clear_textbox()
        returned_variable_class.clear_addresses()
        self.threaded_scan(self.ent1.get())
        while True:
            if returned_variable_class.finished:
                self.txtbox1.configure(state="normal")
                for addr in returned_variable_class.scanned_addrsses:
                    self.txtbox1.insert(END, addr + "\n")
                self.txtbox1.configure(state="disabled")
                break

    def threaded_writer(self):
        writer = threading.Thread(target=self.write_to_textbox)
        writer.start()

    def pick_target(self):
        target = self.lstbox1.get(self.lstbox1.curselection())
        self.ent1.delete(0, END)
        self.ent1.insert(0, target)

    def __call__(self):
        self.window.mainloop()


if __name__ == "__main__":
    program = Program()
    program()
