#!/usr/bin/python
# Matasano PFI (Port Forwarding Interceptor)
# 
# 
#   Stephen A. Ridley
#   stephen@matasano.com Dec 2008

from Tkinter import *
import tkFont #for fixed-width windows font problems
from tkMessageBox import *
from tkFileDialog import *
from threading import Thread
import socket
import asyncore
import sys
import os
import time
from binascii import hexlify
from binascii import unhexlify

class WindowList:

    def __init__(self):
        self.dict = {}
        self.callbacks = []

    def add(self, window):
        window.after_idle(self.call_callbacks)
        self.dict[str(window)] = window

    def delete(self, window):
        try:
            del self.dict[str(window)]
        except KeyError:
            # Sometimes, destroy() is called twice
            pass
        self.call_callbacks()

    def add_windows_to_menu(self,  menu):
        list = []
        for key in self.dict.keys():
            window = self.dict[key]
            try:
                title = window.get_title()
            except TclError:
                continue
            list.append((title, window))
        list.sort()
        for title, window in list:
            menu.add_command(label=title, command=window.wakeup)

    def register_callback(self, callback):
        self.callbacks.append(callback)

    def unregister_callback(self, callback):
        try:
            self.callbacks.remove(callback)
        except ValueError:
            pass

    def call_callbacks(self):
        for callback in self.callbacks:
            try:
                callback()
            except:
                print "warning: callback failed in WindowList", \
                      sys.exc_type, ":", sys.exc_value

registry = WindowList()
add_windows_to_menu = registry.add_windows_to_menu
register_callback = registry.register_callback
unregister_callback = registry.unregister_callback

class ListedToplevel(Toplevel):

    def __init__(self, master, **kw):
        Toplevel.__init__(self, master, kw)
        registry.add(self)
        self.focused_widget = self

    def destroy(self):
        registry.delete(self)
        Toplevel.destroy(self)
        # If this is Idle's last window then quit the mainloop
        # (Needed for clean exit on Windows 98)
        if not registry.dict:
            self.quit()

    def update_windowlist_registry(self, window):
        registry.call_callbacks()

    def get_title(self):
        # Subclass can override
        return self.wm_title()

    def wakeup(self):
        try:
            if self.wm_state() == "iconic":
                self.wm_withdraw()
                self.wm_deiconify()
            self.tkraise()
            self.focused_widget.focus_set()
        except TclError:
            # This can happen when the window menu was torn off.
            # Simply ignore it.
            pass

class MainWindow(Tk):
    """
        This is just a small container class for the main Tk() window
        class
    """
    from Tkinter import Toplevel
    def __init__(self):
        Tk.__init__(self)
        self.title(string="...ooo000OOO  Matasano PFI (Port Forwarding Interceptor)  OOO000ooo...")
        self.out_win = OutputWindow(root=self)
        self.stdout = self.out_win.stdout
        self.stderr = self.out_win.stderr

class SecondaryWindow(Toplevel):
    """
        This is a small container class for Toplevel type secondary windows.
    """
    def __init__(self, parent=None):
        Toplevel.__init__(self)
        self.title(string="...ooo000OOO TRAFFIC EDITOR WINDOW OOO000ooo...")
        self.editor_win = EditorWindow(root=self)
        self.stdout = self.editor_win.stdout
        self.stderr = self.editor_win.stderr

class EditorWindow:
    """
    """
    def __init__(self, root=None):
        self.root = root
        self.top = top = root
        self.tv_frame = tv_frame = Frame(top)
        if os.name in ('nt', 'win', 'windows'): #Fix for windows fixed width font prob.
            self.tv = tv = Text(tv_frame, name='text', padx=5, wrap='char',
                    foreground="black",
                    background="white",
                    font=tkFont.Font(family="FixedSys", size=8),
                    highlightcolor="white",
                    highlightbackground="purple",
                    width = 80,
                    height = 25)
        else:
            self.tv = tv = Text(tv_frame, name='text', padx=5, wrap='char',
                    foreground="black",
                    background="white",
                    highlightcolor="white",
                    highlightbackground="purple",
                    width = 80,
                    height = 25)
#                state = 'disabled')
        self.tv.bind("<Key>", self.key_handler)
        self.vbar = vbar = Scrollbar(tv_frame, name='vbar')
        vbar['command'] = tv.yview
        vbar.pack(side=RIGHT, fill=Y)
        tv['yscrollcommand'] = vbar.set
        fontWeight = 'normal'
        pass_button = Button(tv_frame, text="I am done modifying the traffic, pass it along!",
            state="active", command=self.use_edit, activeforeground="green")
        cancel_button = Button(tv_frame, text="Nevermind! Just pass the traffic as it was before I messed with it.",
            state="active", command=self.cancel_edit, activeforeground="red")
        cancel_button.pack(side=BOTTOM, fill=X)
        pass_button.pack(side=BOTTOM, fill=X)
        #probably should perform tv.config() here
        tv_frame.pack(side=LEFT, fill=BOTH, expand=1)
        tv.pack(side=TOP, fill=BOTH, expand=1)
        tv.focus_set()
        self.stderr = PseudoFile(self)
        self.stdout = PseudoFile(self)
        self.bufstate = 0 # 0 is nothing is ready yet
                          # 1 is that data is ready and can be read from
                          #     self.textbuf 
                          # 2 is that editting was cancelled
        self.textbuf=""
                
    def oprint(self, text_to_print):
        """
            This function will be exposed externally to allow others to
        print to our window.
        """
        self.tv.insert(END, text_to_print)

    def use_edit(self):
        self.textbuf = self.tv.get("1.0", END)
        self.bufstate = 1
        self.clear_scrollback()

    def cancel_edit(self):
        self.textbuf = ""
        self.bufstate = 2
        self.clear_scrollback()

    def clear(self):
        self.bufstate = 0
        self.textbuf = ""
        self.clear_scrollback() 

    def key_handler(self, event):
        """
        """
        pass

    def clear_scrollback(self):
        """
            Clear the scrollback of the text window.
        """
        self.tv.delete("1.0", END)

class OutputWindow:
    """
    """
    def __init__(self, root=None):
        self.root = root
        self.top = top = root
        self.tv_frame = tv_frame = Frame(top)
        if os.name in ('nt', 'win', 'windows'): #Fix for windows fixed width font prob.
            self.tv = tv = Text(tv_frame, name='text', padx=5, wrap='char',
                    foreground="black",
                    background="white",
                    font=tkFont.Font(family="FixedSys", size=8),
                    highlightcolor="white",
                    highlightbackground="purple",
                    width = 80, 
                    height = 25) 
        else:
            self.tv = tv = Text(tv_frame, name='text', padx=5, wrap='char',
                    foreground="black",
                    background="white",
                    highlightcolor="white",
                    highlightbackground="purple",
                    width = 80, 
                    height = 25) 

        self.tv.bind("<Key>", self.key_handler)
        self.vbar = vbar = Scrollbar(tv_frame, name='vbar')
        vbar['command'] = tv.yview
        vbar.pack(side=RIGHT, fill=Y)
        tv['yscrollcommand'] = vbar.set
        fontWeight = 'normal'
        def_trigger_button = Button(tv_frame, text="Select a file to execute as traffic comes in.",
            state="active", command=self.set_plugin_trigger)
        save_buffer_button = Button(tv_frame, text="Save scrollback buffer to file.",
            state="active", command=self.save_buffer_to_file)
        clear_button = Button(tv_frame, text="Clear scrollback buffer",
            state="active", command=self.clear_scrollback)
        def_trigger_button.pack(side=BOTTOM, fill=X)
        save_buffer_button.pack(side=BOTTOM, fill=X)
        clear_button.pack(side=BOTTOM, fill=X)
        self.li = IntVar() 
        self.ri = IntVar()
        remote_intercept = Checkbutton(tv_frame, text="Intercept on Remote Side?", variable=self.ri, onvalue=1, offvalue=0)
        local_intercept = Checkbutton(tv_frame, text="Intercept on Local Side?", variable=self.li, onvalue=1, offvalue=0)
        remote_intercept.pack(side=BOTTOM)
        local_intercept.pack(side=BOTTOM)
        #probably should perform tv.config() here
        tv_frame.pack(side=LEFT, fill=BOTH, expand=1)
        tv.pack(side=TOP, fill=BOTH, expand=1)
        tv.focus_set()
        self.stderr = PseudoFile(self)
        self.stdout = PseudoFile(self)
        self.plugin_filename = "" 
#        if os.name in ('nt', 'win', 'windows'):
#            self.tmpdir = os.getenv("TEMP")
#        else:
#            self.tmpdir = os.getenv("TMPDIR")
#        if self.tmpdir == None: # that environment variable didnt exist.
#            showinfo("TEMP DIRECTORY NOT FOUND", "A directory suitable for my temp files could not be found, please point me at one. Thanks.")
#            self.tmpdir = askdirectory()
#            showinfo("TEMP DIRECTORY SELECTED", ("Using %s as my temp directory" % self.tmpdir))

    def oprint(self, text_to_print):
        """
            This function will be exposed externally to allow others to
        print to our window.
        """
        self.tv.insert(END, text_to_print)

    def key_handler(self, event):
        """
        """
        pass

    def clear_scrollback(self):
        """
            Clear the scrollback of the text window.
        """
        self.tv.delete("1.0", END)
    
    def set_plugin_trigger(self):
        message = """
HOW PLUGINS WORK:

After this informational window you will be prompted to select a file.
This file will be executed with the same environment as PFI
and receive the bytes intercepted via STDIN in raw byte format.
The data "returned" from your plugin is passed back to PFI
on STDOUT and must also be in raw byte format

your_plugin.[sh,exe,bat,py,rb,whatever] <bytes written>

    <num bytes> : The number of bytes that the plugin can
    anticipate will be passed to it via STDIN

"""
        showinfo("A BIT ABOUT HOW THIS WORKS", message)             
        f_h = askopenfile('r')
        self.plugin_filename = f_h.name
        message = "Passing all intercepted data to:  %s" % f_h.name
        showinfo("EXECUTABLE SELECTED", message)
        f_h.close()

    def save_buffer_to_file(self):
        f_h = asksaveasfile('w')
        if f_h is not None:
            header = "\n=================\nMatasano PFI Log\n%s\n=================\n" % (time.asctime())
            f_h.write(header)
            data = self.tv.get("1.0", END)
            f_h.write(data)
            f_h.flush()
            f_h.close()
            message =  ("Wrote %d bytes from scrollback buffer into logfile: %s") % (len(data), f_h.name)
            showinfo("LOG FILE WRITTEN", message)

class PseudoFile:
    """
        This is used to overload sys.stderr and sys.stdout.
        the object reference passed in on "window_obj" must
        have an "oprint" method.
    """
    def __init__(self, window_obj, encoding=None):
        self.encoding = encoding
        self.window_obj = window_obj

    def write(self, s):
        self.window_obj.oprint(s)

    def writelines(self, l):
        map(self.write, l)

    def flush(self):
        pass

    def isatty(self):
        return True

class VisualizerWindow:
    """
        This is the window that displays the TreeView of the compiled
        Session object.
    """
    def __init__(self, root=None):
        self.root = root
        self.vbar = vbar = Scrollbar(name='vbar')
        self.top = top = root
        self.tv_frame = tv_frame = Frame(top)

class forwarder(asyncore.dispatcher):
    def __init__(self, ip, port, remoteip,remoteport,rootWindow, outputWindow, backlog=5):
        asyncore.dispatcher.__init__(self)
        self.remoteip=remoteip
        self.remoteport=remoteport
        self.localip = ip
        self.localport = port
        self.create_socket(socket.AF_INET,socket.SOCK_STREAM)
        self.set_reuse_addr()
        self.bind((ip,port))
        self.listen(backlog)
        self.rootWin = rootWindow
        self.outputWin = outputWindow

    def handle_accept(self):
        conn, addr = self.accept()
        # print '--- Connect --- '
        print "Incoming connect on %s:%d." % (self.localip, self.localport)
        sender(receiver(conn, self.rootWin, self.outputWin),self.remoteip,self.remoteport, self.rootWin, self.outputWin)

class receiver(asyncore.dispatcher):
    def __init__(self,conn, rootWin, outputWin):
        asyncore.dispatcher.__init__(self,conn)
        self.from_remote_buffer=''
        self.to_remote_buffer=''
        self.sender=None
        self.rootWin = rootWin
        self.outputWin = outputWin
        self.conn = conn

    def handle_connect(self):
        pass

    def handle_read(self):
        read = self.recv(4096)
        tmp_buf = ""
        saved_buf = read #used if the user edits
        if (self.rootWin.out_win.li.get() == 1) and (self.rootWin.out_win.plugin_filename == ""): #Checkbox value
            print "THE FOLLOWING %d BYTES WERE INTERCEPTED FROM THE LOCAL SIDE!." % (len(read))
            print "(See the Editor Window to edit these bytes.)"
            hexdump(read)
            for byte in read:
                tmp_buf+='\\'+'x'+hexlify(byte)
            self.outputWin.editor_win.oprint(tmp_buf)
            while self.outputWin.editor_win.bufstate not in (1,2):
                pass 
            if (self.outputWin.editor_win.bufstate == 1):
                print repr(self.outputWin.editor_win.textbuf.replace('\\x',''))
                self.from_remote_buffer += unhexlify(self.outputWin.editor_win.textbuf.replace('\\x','').strip())
                print ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
                print "\nSending modified buffer."
                hexdump(self.from_remote_buffer)
                print ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
                self.outputWin.editor_win.clear()
            if self.outputWin.editor_win.bufstate == 2: #the user cancelled
                self.from_remote_buffer += read
                self.outputWin.editor_win.clear()
        elif (self.rootWin.out_win.plugin_filename != ""):
            print "%d BYTES WERE INTERCEPTED FROM THE LOCAL SIDE!." % (len(read))
            print "Passing to the plugin %s" % (self.rootWin.out_win.plugin_filename)
            h_in, h_out = os.popen2(self.rootWin.out_win.plugin_filename, 'b')
            h_in.write(read)
            h_in.close()
            somedataread = False
            fromplugin = ""
            while 1:
                try:
                    fromplugin+=h_out.next()
                    if len(fromplugin) > 0: #that means *some* data has been read
                        somedataread = True
                except StopIteration: #this exception will hit until there is data ready
                                       #we want to wait for it to hit *after* we've read
                                        #some data, indicating that there is no more data ready
                    if somedataread == True:
                        print ("Got %d bytes returned from plugin" % len(fromplugin))
                        break
#            showinfo("PLUGIN DATA RECEIVED!", "Got %d bytes back from plugin." % len(fromplugin))
            hexdump(fromplugin)
            self.from_remote_buffer += fromplugin
        else:
            print ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
            hexdump(read)
            self.from_remote_buffer += read
            print ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"

    def writable(self):
        return (len(self.to_remote_buffer) > 0)

    def handle_write(self):
        tmp_buf = ""
        saved_buf = self.to_remote_buffer #used if the user edits
        if (self.rootWin.out_win.ri.get() == 1) and (self.rootWin.out_win.plugin_filename == ""): #Checkbox value
            print "THE FOLLOWING %d BYTES WERE INTERCEPTED FROM THE REMOTE SIDE!." % (len(self.to_remote_buffer))
            print "(See the Editor Window to edit these bytes.)"
            hexdump(self.to_remote_buffer)
            for byte in self.to_remote_buffer:
                tmp_buf+='\\'+'x'+hexlify(byte)
            self.outputWin.editor_win.oprint(tmp_buf)
            while self.outputWin.editor_win.bufstate not in (1,2):
                pass 
            if (self.outputWin.editor_win.bufstate == 1):
                print repr(self.outputWin.editor_win.textbuf.replace('\\x',''))
                self.to_remote_buffer = unhexlify(self.outputWin.editor_win.textbuf.replace('\\x','').strip())
                print "<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
                print "\nSending modified buffer."
                hexdump(self.to_remote_buffer)
                print "<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
                sent = self.send(self.to_remote_buffer)
                self.outputWin.editor_win.clear()
            if self.outputWin.editor_win.bufstate == 2: #the user cancelled
                sent = self.send(self.to_remote_buffer)
                self.outputWin.editor_win.clear()
        elif (self.rootWin.out_win.plugin_filename != ""):
            print "%d BYTES WERE INTERCEPTED FROM THE REMOTE SIDE!." % (len(self.to_remote_buffer))
            print "Passing to the plugin %s" % (self.rootWin.out_win.plugin_filename)
            h_in, h_out = os.popen2(self.rootWin.out_win.plugin_filename, 'b')
            h_in.write(self.to_remote_buffer)
            h_in.close()
            somedataread = False
            fromplugin = ""
            while 1:
                try:
                    fromplugin+=h_out.next()
                    if len(fromplugin) > 0: #that means *some* data has been read
                        somedataread = True
                except StopIteration: #this exception will hit until there is data ready
                                       #we want to wait for it to hit *after* we've read
                                        #some data, indicating that there is no more data ready
                    if somedataread == True:
                        print ("Got %d bytes returned from plugin, data from PLUGIN below:" % len(fromplugin))
                        break
#            showinfo("PLUGIN DATA RECEIVED!", "Got %d bytes back from plugin." % len(fromplugin))
            hexdump(fromplugin)
            sent = self.send(self.to_remote_buffer)
        else:    
            print "<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
            hexdump(self.to_remote_buffer)
            sent = self.send(self.to_remote_buffer)
            print "<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
        #print '%04i <--'%sent
        self.to_remote_buffer = self.to_remote_buffer[sent:]

    def handle_close(self):
        self.close()
        if self.sender:
            self.sender.close()

def hexdump(src, length=16):
    N=0; result=''
    FILTER=''.join([(len(repr(chr(x)))==3) and chr(x) or '.' for x in range(256)])
    while src: 
        s,src = src[:length],src[length:]
        hexa = ' '.join(["%02X"%ord(x) for x in s])  
        s = s.translate(FILTER)
        result += "%08X:  %-*s  |%s|\n" % (N, length*3, hexa, s)
        N+=length
    print result

class sender(asyncore.dispatcher):
    """
        This handles the remote connection.
    """
    def __init__(self, receiver, remoteaddr,remoteport, rootWin, outputWin):
        asyncore.dispatcher.__init__(self)
        self.receiver=receiver
        receiver.sender=self
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connect((remoteaddr, remoteport))
        self.rootWin = rootWin
        self.outputWin = outputWin

    def handle_connect(self):
        pass

    def handle_read(self):
        read = self.recv(4096)
        # print '<-- %04i'%len(read)
        self.receiver.to_remote_buffer += read

    def writable(self):
        return (len(self.receiver.from_remote_buffer) > 0)

    def handle_write(self):
        sent = self.send(self.receiver.from_remote_buffer)
        # print '--> %04i'%sent
        self.receiver.from_remote_buffer = self.receiver.from_remote_buffer[sent:]

    def handle_close(self):
        self.close()
        self.receiver.close()


if __name__=='__main__':
    import optparse
    parser = optparse.OptionParser()

    parser.add_option(
        '-l','--local-ip',
        dest='local_ip',default='127.0.0.1',
        help='Local IP address to bind to')
    parser.add_option(
        '-p','--local-port',
        type='int',dest='local_port',default=80,
        help='Local port to bind to')
    parser.add_option(
        '-r','--remote-ip',dest='remote_ip',
        help='Local IP address to bind to')
    parser.add_option(
        '-P','--remote-port',
        type='int',dest='remote_port',default=80,
        help='Remote port to bind to')
    if len(sys.argv) == 1:
        sys.argv.append("--help")

    options, args = parser.parse_args()
    rootWindow = MainWindow()
    outputWindow = SecondaryWindow()

    #We overload the normal stdout/stderr to go to our 
    #output window
    global saved_stderr, saved_stdout
    saved_stderr = sys.stderr
    saved_stdout = sys.stdout
    sys.stderr = rootWindow.stderr
    sys.stdout = rootWindow.stdout
    forwarder(options.local_ip,options.local_port,options.remote_ip,options.remote_port, rootWindow, outputWindow)
    Thread(target=asyncore.loop, args=[]).start()
    rootWindow.mainloop()
    rootWindow.destroy()

