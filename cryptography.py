from Crypto.Random import random
from Crypto.Cipher import AES

import tkinter as tk
from tkinter import *
from operator import xor
import base64
import hashlib

import cv2
from PIL import Image, ImageTk
from tkinter import messagebox

root = Tk()
root.title('Cryptography')
root.geometry("1023x768+470+100")
root.resizable(0,0)




win = Toplevel(root)
win.title("RSP")
win.geometry("1023x768+470+100")
win.resizable(0,0)
win.withdraw()
win1 = Toplevel(root)
win1.title("AES")
win1.geometry("1023x768+470+100")
win1.resizable(0,0)
win1.withdraw()
global l1,l2,i,j
l1=[]
l2=[]
i=0
j=0

BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

def send1():
    global l1
    global e4
    global i

    if i<15:

        l1.append(e4.get())
        e4.delete(0,END)
        i += 1
        Label(win, text="pi-s(" + str(i) + ")=", font=("Chilanka", 16), fg='white', bg='DeepSkyBlue4', height=1,
              padx=10, pady=10).place(x=120, y=300)
        e4 = Entry(win)
        e4.config(font=("Chilanka", 16), fg='gray8', bg='white', width=28)
        e4.place(x=300, y=308)
        if i==16:
            l1.append(e4.get())

        button = Button(win, text='send', command=send1)
        button.config(font=("Chilanka", 23), bg='DeepSkyBlue4', fg='white', activebackground='DeepSkyBlue4',
                      activeforeground='gray8')
        button.place(x=750, y=300)


def send2():

    global l2
    global e5
    global j
    if j<16:
        l2.append(e5.get())
        e5.delete(0, END)
        j+=1
        Label(win, text="pi-p(" + str(j + 1) + ")=", font=("Chilanka", 16), fg='white', bg='DeepSkyBlue4', height=1,
              padx=10, pady=10).place(x=120, y=380)
        e5 = Entry(win)
        e5.config(font=("Chilanka", 16), fg='gray8', bg='white', width=28)
        e5.place(x=300, y=388)
        if j==16:
            l2.append(e5.get())

        button1 = Button(win, text='send', command=send2)
        button1.config(font=("Chilanka", 23), bg='DeepSkyBlue4', fg='white', activebackground='DeepSkyBlue4',
                       activeforeground='gray8')
        button1.place(x=750, y=380)

def listedesk(k,r):
    l=[]
    for i in range(1,r+2):
        l.append(k[r*i-4:r*i+12])
    return l

def encrypt():
    global e1, e2, e3, e4, e5, e6
    global x, m, lk,l1,l2
    lk = []
    k = e2.get()
    s = 0
    m = int(e3.get())
    lk = listedesk(k, m)
    # I must recuperate data of entries in function encrypt
    x = e1.get()
    if len(x)!=16:
        # canvas = Canvas(win, width=340,height=30)
        # canvas.create_text(5, 12,  font="Chilanka 14 italic bold", text="Length of number must be 16!")

        messagebox.showerror("Error", "length of text must be 16")
        e1.delete(0, END)
    elif len(k)!=32:
        messagebox.showerror("Error", "length of key must be 32")
        # Label(win, text="length of key must be 32",fg="red").grid(row=1, column=2)
        e2.delete(0, END)
    else:
        w = x
        m = int(m)
        for i in range(0, m - 1):
            u = xor(int(w, 2), int(lk[i], 2))
            v = ''
            h = 0
            u = str(bin(u)[2:].zfill(16))

            for j in range(1, m + 1):
                a = u[h:h + 4]
                h += 4
                a = int(a, 2)
                v += str(l1[a])
            v = int(v, 16)
            v = str(bin(v)[2:].zfill(16))
            w = ''

            for b in range(0, 16):
                s = int(l2[b])
                w += v[s - 1]
        w = str(w)
        comp = str(lk[m - 1])
        u = xor(int(w, 2), int(comp, 2))
        v = ''
        h = 0
        u = str(bin(u)[2:].zfill(16))
        for j in range(1, m + 1):
            a = u[h:h + 4]
            h += 4
            a = int(a, 2)
            v += str(l1[a])
        v = int(v, 16)
        v = str(bin(v)[2:].zfill(16))
        compteur1 = str(lk[m])
        res = bin(xor(int(v, 2), int(compteur1, 2)))
        res = res[2:]
        e6.delete(0, END)
        e6.insert(0, res)

def rsp():
        global e1,e2,e3,e4,e5,e6
        global x,m,lk,l1,l2,i,j
        win.deiconify()
        rot = Image.open("broadband.jpg")
        # rot = Image.open("fond.jpg")
        rotunda = ImageTk.PhotoImage(rot)
        label2 = Label(win, image=rotunda)
        label2.image = rotunda
        label2.place(x=0, y=0, relwidth=1, relheight=1)

        Label(win, text="Enter binary text of 16 bit to encrypt: ",font=("Chilanka",16),fg='white',bg='DeepSkyBlue4',height=1,padx=10,pady=10).place(x=20,y=60)
        Label(win, text="Enter encryption key: ",font=("Chilanka",16),fg='white',bg='DeepSkyBlue4',height=1,padx=10,pady=10).place(x=20,y=140)
        Label(win, text="Enter number of round: ",font=("Chilanka",16),fg='white',bg='DeepSkyBlue4',height=1,padx=10,pady=10).place(x=20,y=220)
        e1 = Entry(win)
        e2 = Entry(win)
        e3=Entry(win)
        e1.config(font=("Chilanka",16),fg='gray8',bg='white',width=28)
        e2.config(font=("Chilanka",16),fg='gray8',bg='white',width=28)
        e3.config(font=("Chilanka",16),fg='gray8',bg='white',width=28)
        e1.place(x=540,y=68)
        e2.place(x=540,y=148)
        e3.place(x=540,y=228)
        Label(win,text="pi-s(" + str(i) + ")=",font=("Chilanka",16),fg='white',bg='DeepSkyBlue4',height=1,padx=10,pady=10).place(x=120,y=300)
        e4=Entry(win)
        e4.config(font=("Chilanka",16),fg='gray8',bg='white',width=28)
        e4.place(x=300,y=308)
        button=Button(win,text='send',command=send1)
        button.config(font=("Chilanka", 23),bg='DeepSkyBlue4',fg='white',activebackground='DeepSkyBlue4',activeforeground='gray8')
        button.place(x=750,y=300)
        Label(win, text="pi-p(" + str(j+1) + ")=",font=("Chilanka",16),fg='white',bg='DeepSkyBlue4',height=1,padx=10,pady=10).place(x=120,y=380)
        e5 = Entry(win)
        e5.config(font=("Chilanka",16),fg='gray8',bg='white',width=28)
        e5.place(x=300,y=388)
        button1 = Button(win, text='send', command=send2)
        button1.config(font=("Chilanka", 23),bg='DeepSkyBlue4',fg='white',activebackground='DeepSkyBlue4',activeforeground='gray8')
        button1.place(x=750,y=380)
        button2 = Button(win, text='       Encrypt       ', command=encrypt,padx=2,pady=8)
        button2.config(font=("Chilanka", 23),bg='gray8',fg='white',activebackground='DeepSkyBlue4',activeforeground='gray8')
        button2.place(x=345,y=490)
        Label(win, text="    Answer:    ",font="Chilanka 22 bold",fg='white',bg='DeepSkyBlue4',height=1,padx=10,pady=20).place(x=120,y=600)
        e6 = Entry(win)
        e6.config(font="Chilanka 22 bold",fg='gray8',bg='white',width=21,justify='center')
        e6.place(x=430,y=612,height=60)
def AesEncrypt():
    global a1,a2
    txt=a1.get()
    key=a2.get()
    private_key = hashlib.sha256(key.encode("utf-8")).digest()
    txt= pad(txt)
    iv = random.new().read(AES.block_size)
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    res= base64.b64encode(iv + cipher.encrypt(txt))
    Label(win1, text="Encrypted message is:",font="Chilanka 16 bold",fg='white',bg='DeepSkyBlue4',height=1,padx=10,pady=12).place(x=40,y=490)
    a3 = Entry(win1,width=79)
    a3.config(font="Chilanka 12 bold", fg='gray8', bg='white', justify='center')
    a3.place(x=40, y=600, height=60)
    a3.delete(0, END)
    a3.insert(0, res)
def AesDecrypt():
    global a1,a2
    txt=a1.get()
    key=a2.get()
    private_key = hashlib.sha256(key.encode("utf-8")).digest()
    txt = base64.b64decode(txt)
    iv = txt[:16]
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    res1= unpad(cipher.decrypt(txt[16:]))
    Label(win1, text="Encrypted message is:", font="Chilanka 16 bold", fg='white', bg='DeepSkyBlue4', height=1, padx=10,
          pady=12).place(x=40, y=490)
    a3 = Entry(win1, width=79)
    a3.config(font="Chilanka 12 bold", fg='gray8', bg='white', justify='center')
    a3.place(x=40, y=600, height=60)
    a3.delete(0, END)
    a3.insert(0, res1)
def aes():
    global a1,a2
    win1.deiconify()  
    rot = Image.open("broadband.jpg")
    # rot = Image.open("fond.jpg")
    rotunda = ImageTk.PhotoImage(rot)
    label2 = Label(win1, image=rotunda)
    label2.image = rotunda
    label2.place(x=0, y=0, relwidth=1, relheight=1)    

    Label(win1, text="Enter text to encrypt or to decrypt:",font=("Chilanka",16),fg='white',bg='DeepSkyBlue4',height=1,padx=10,pady=10).place(x=28,y=80)
    Label(win1, text="Enter encryption key:",font=("Chilanka",16),fg='white',bg='DeepSkyBlue4',height=1,padx=10,pady=10).place(x=28,y=160)
    a1=Entry(win1)
    a2=Entry(win1)
    a1.config(font=("Chilanka",16),fg='gray8',bg='white',width=28)
    a2.config(font=("Chilanka",16),fg='gray8',bg='white',width=28)
    a1.place(x=540,y=88)
    a2.place(x=540,y=168)
    button1 = Button(win1, text='    Encrypt    ', command=AesEncrypt,padx=2,pady=8)
    button1.config(font=("Chilanka", 23),bg='gray8',fg='white',activebackground='DeepSkyBlue4',activeforeground='gray8')
    button1.place(x=280,y=300)
    button2 = Button(win1, text='    Decrypt    ', command=AesDecrypt, padx=2, pady=8)
    button2.config(font=("Chilanka", 23), bg='gray8', fg='white', activebackground='DeepSkyBlue4',
                   activeforeground='gray8')
    button2.place(x=520, y=300)



 # create root window

# put a button on it, or a menu
rot = Image.open("broadband.jpg")
# rot = Image.open("fond.jpg")
rotunda = ImageTk.PhotoImage(rot)
label2 = Label(root, image=rotunda)
label2.image = rotunda
label2.pack()
T = Text(root, height=1, width=38,padx=2,pady=15)
T.config(font=("Chilanka", 24),bg='gray8',fg='white')
T.place(x="100",y="70")
T.insert(END, "      Choose the method of cryptography:\n")

b1=Button(root, text='RSP', command=rsp,height=1, width=20,padx=2,pady=8)
b1.place(x=300,y=260)
b1.config(font=("Chilanka", 23),bg='gray8',fg='white',activebackground='DeepSkyBlue4',activeforeground='gray8')
b2=Button(root, text='AES', command=aes,height=1, width=20,padx=2,pady=8)
b2.place(x=300,y=490)
b2.config(font=("Chilanka", 23),bg='gray8',fg='white',activebackground='DeepSkyBlue4',activeforeground='gray8')
 # start event-loop
root.mainloop()
