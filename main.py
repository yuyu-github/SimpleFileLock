from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto import Random
from enum import Enum, Flag, auto
import hashlib
import os
import re
from typing import Callable
import wx

class HashAlgorithm(Enum):
  SHA256 = 0
DEFALUT_HASH_ALGORITHM = HashAlgorithm.SHA256

class EncryptionAlgorithm(Enum):
  AES_CTR = 0
DEFAULT_ENCRYPTION_ALGORITHM = EncryptionAlgorithm.AES_CTR
  
class _Hash:
  def __init__(self, to_bytes: Callable[[], bytes], to_string: Callable[[], str]):
    self.to_bytes = to_bytes
    self.to_string = to_string
  
def hash(data: bytes, algorithm: HashAlgorithm = DEFALUT_HASH_ALGORITHM):
  match algorithm:
    case HashAlgorithm.SHA256:
      hashed = hashlib.sha256(data)
      return _Hash(hashed.digest, hashed.hexdigest)
    
def encrypt(data: bytes, key: bytes, algorithm: EncryptionAlgorithm = DEFAULT_ENCRYPTION_ALGORITHM):
  match algorithm:
    case EncryptionAlgorithm.AES_CTR:
      iv = Random.new().read(AES.block_size)
      ctr = Counter.new(AES.block_size * 8, initial_value=int.from_bytes(iv, 'big'))
      aes = AES.new(key, AES.MODE_CTR, counter=ctr)
      cipher = aes.encrypt(data)
      return (cipher, iv)
    
def decrypt(cipher: bytes, key: bytes, decryption_meta: bytes, algorithm: EncryptionAlgorithm = DEFAULT_ENCRYPTION_ALGORITHM):
  match algorithm:
    case EncryptionAlgorithm.AES_CTR:
      iv = decryption_meta
      ctr = Counter.new(AES.block_size * 8, initial_value=int.from_bytes(iv, 'big'))
      aes = AES.new(key, AES.MODE_CTR, counter=ctr)
      data = aes.decrypt(cipher)
      return data
    
def lock(path, encryption_key):
  confirm_meta = encryption_key
  
  newpath = re.sub(r'\.runsfl$', '.sfl', path) if path.endswith('.runsfl') else path + '.sfl'
  with open(path, 'rb') as org, open(newpath, 'wb') as locked:
    (cipher, decryption_meta) = encrypt(len(confirm_meta).to_bytes(2, 'big') + confirm_meta + org.read(), encryption_key)
    locked.write(DEFALUT_HASH_ALGORITHM.value.to_bytes(1, 'big') + DEFAULT_ENCRYPTION_ALGORITHM.value.to_bytes(1, 'big') + \
      len(decryption_meta).to_bytes(2, 'big') + decryption_meta + cipher)

def unlock(path, decryption_key):
  newpath = re.sub(r'\.sfl$', '', path)
  with open(path, 'rb') as locked, open(newpath, 'wb') as org:
    locked.seek(1)
    encryption_algorithm = EncryptionAlgorithm(int.from_bytes(locked.read(1), 'big'))
    decryption_meta_len = int.from_bytes(locked.read(2), 'big')
    decryption_meta = locked.read(decryption_meta_len)
    cipher = locked.read()
    
    data = decrypt(cipher, decryption_key, decryption_meta, encryption_algorithm)
    confirm_meta_len = int.from_bytes(data[0:2], 'big')
    confirm_meta = data[2:2+confirm_meta_len]

    if confirm_meta == decryption_key:
      org.write(data[2+confirm_meta_len:])
    else:
      wx.MessageBox('パスワードが間違っています', 'エラー')
  
def open_file(paths: list[str]):
  lock_files = []
  unlock_files = []
  
  for path in paths:
    ext = os.path.splitext(path)[1]
    if ext == '.sfl': unlock_files.append(path)
    else: lock_files.append(path)
    
  if len(lock_files) >= 1: LockFrame(lock_files).Show(True)

class SimpleFileLock(wx.App):
  def OnInit(self):
    StartFrame().Show(True)
    return True
  
class StartFrame(wx.Frame):
  def __init__(self):
    super().__init__(None, title='Simple File Lock', size=(300, 250))
    self.SetBackgroundColour('white')
    self.SetWindowStyle(wx.DEFAULT_FRAME_STYLE & ~(wx.RESIZE_BORDER | wx.MAXIMIZE_BOX))

    panel = wx.Panel(self)
    sizer = wx.GridSizer(3, 1, (0, 0))
    panel.SetSizer(sizer)
    
    lock_file_button = wx.Button(panel, label='ファイルをロック')
    lock_file_button.SetBackgroundColour('#F0F0F0')
    lock_file_button.Bind(wx.EVT_BUTTON, self.on_lock_file_button_pressed)
    sizer.Add(lock_file_button, flag=wx.GROW | wx.ALL, border=5)
    
    unlock_file_button = wx.Button(panel, label='ファイルをアンロック')
    unlock_file_button.SetBackgroundColour('#F0F0F0')
    unlock_file_button.Bind(wx.EVT_BUTTON, self.on_unlock_file_button_pressed)
    sizer.Add(unlock_file_button, flag=wx.GROW | wx.ALL, border=5)
    
    edit_file_button = wx.Button(panel, label='ファイルを編集')
    edit_file_button.SetBackgroundColour('#F0F0F0')
    edit_file_button.Bind(wx.EVT_BUTTON, self.on_edit_file_button_pressed)
    sizer.Add(edit_file_button, flag=wx.GROW | wx.ALL, border=5)
    
  def on_lock_file_button_pressed(self, event):
    dialog = wx.FileDialog(self, 'ファイルの選択')
    dialog.SetWindowStyle(wx.FD_OPEN | wx.FD_FILE_MUST_EXIST | wx.FD_MULTIPLE)
    dialog.SetWildcard('すべてのファイル(*.*)|*.*|SimpleFileLock実行ファイル(*.runsfl)|*.runsfl')

    if dialog.ShowModal() == wx.ID_OK:
      paths = dialog.GetPaths()
      if len(paths) >= 1:
        LockFrame(paths).Show(True)
        
  def on_unlock_file_button_pressed(self, event):
    dialog = wx.FileDialog(self, 'ファイルの選択')
    dialog.SetWindowStyle(wx.FD_OPEN | wx.FD_FILE_MUST_EXIST | wx.FD_MULTIPLE)
    dialog.SetWildcard('SimpleFileLockファイル(*.sfl)|*.sfl')

    if dialog.ShowModal() == wx.ID_OK:
      paths = dialog.GetPaths()
      for path in paths:
        UnlockFrame(path).Show(True)
        
  def on_edit_file_button_pressed(self, event):
    dialog = wx.FileDialog(self, 'ファイルの選択')
    dialog.SetWindowStyle(wx.FD_OPEN | wx.FD_FILE_MUST_EXIST | wx.FD_MULTIPLE)
    dialog.SetWildcard('SimpleFileLockファイル(*.sfl)|*.sfl')

    if dialog.ShowModal() == wx.ID_OK:
      paths = dialog.GetPaths()
      if len(paths) >= 1:
        pass
      
class LockFrame(wx.Frame):
  def __init__(self, paths: list[str]):
    self.paths = paths
    
    name = str(len(paths)) + '個のファイル' if len(paths) >= 2 else os.path.basename(paths[0])
    super().__init__(None, title=name + 'をロック', size=(400, 150))
    self.SetBackgroundColour('white')
    self.SetWindowStyle(wx.DEFAULT_FRAME_STYLE & ~(wx.RESIZE_BORDER | wx.MAXIMIZE_BOX))
    
    panel = wx.Panel(self)
    top_sizer = wx.BoxSizer(wx.VERTICAL)
    panel.SetSizer(top_sizer)
    
    sizer = wx.GridBagSizer()
    top_sizer.Add(sizer, 1, flag=wx.EXPAND)

    sizer.Add(wx.StaticText(panel, label='パスワード', style=wx.TE_LEFT), (0, 1), flag=wx.EXPAND | wx.ALIGN_CENTER)
    password_textctrl = wx.TextCtrl(panel, style=wx.TE_PASSWORD)
    self.password_textctrl = password_textctrl
    sizer.Add(password_textctrl, (0, 2), flag=wx.EXPAND | wx.ALL, border=10)

    sizer.AddGrowableCol(2)
    
    btn_sizer = wx.StdDialogButtonSizer()
    top_sizer.Add(btn_sizer, flag=wx.EXPAND | wx.ALL, border=10)

    lock_btn = wx.Button(panel, wx.ID_OK, label='ロック')
    lock_btn.Bind(wx.EVT_BUTTON, lambda event: self.lock())
    lock_btn.SetDefault()
    btn_sizer.AddButton(lock_btn)
    
    cancel_btn = wx.Button(panel, wx.ID_CANCEL, label='キャンセル')
    cancel_btn.Bind(wx.EVT_BUTTON, lambda event: self.Close())
    btn_sizer.AddButton(cancel_btn)
    
    btn_sizer.Realize()
    
  def lock(self):
    hashed_password = hash(str(self.password_textctrl.GetValue()).encode()).to_bytes()

    result = ConfirmPasswordDialog(hashed_password).ShowModal()
    if (result == wx.ID_CANCEL): self.Close()
    elif (result == wx.ID_NO): wx.MessageBox('パスワードが異なっています')
    elif (result == wx.ID_YES):
      try:
        for path in self.paths:
          encryption_key = hashed_password
          lock(path, encryption_key)
      except Exception as e:
        wx.MessageBox(str(e), 'エラーが発生しました')
      finally: self.Close()
      
class UnlockFrame(wx.Frame):
  def __init__(self, path: str):
    self.path = path
    
    name = os.path.basename(path)
    super().__init__(None, title=name + 'をアンロック', size=(400, 150))
    self.SetBackgroundColour('white')
    self.SetWindowStyle(wx.DEFAULT_FRAME_STYLE & ~(wx.RESIZE_BORDER | wx.MAXIMIZE_BOX))
    
    panel = wx.Panel(self)
    top_sizer = wx.BoxSizer(wx.VERTICAL)
    panel.SetSizer(top_sizer)
    
    sizer = wx.GridBagSizer()
    top_sizer.Add(sizer, 1, flag=wx.EXPAND)

    sizer.Add(wx.StaticText(panel, label='パスワード', style=wx.TE_LEFT), (0, 1), flag=wx.EXPAND | wx.ALIGN_CENTER)
    password_textctrl = wx.TextCtrl(panel, style=wx.TE_PASSWORD)
    self.password_textctrl = password_textctrl
    sizer.Add(password_textctrl, (0, 2), flag=wx.EXPAND | wx.ALL, border=10)

    sizer.AddGrowableCol(2)
    
    btn_sizer = wx.StdDialogButtonSizer()
    top_sizer.Add(btn_sizer, flag=wx.EXPAND | wx.ALL, border=10)

    lock_btn = wx.Button(panel, wx.ID_OK, label='アンロック')
    lock_btn.Bind(wx.EVT_BUTTON, lambda event: self.unlock())
    lock_btn.SetDefault()
    btn_sizer.AddButton(lock_btn)
    
    cancel_btn = wx.Button(panel, wx.ID_CANCEL, label='キャンセル')
    cancel_btn.Bind(wx.EVT_BUTTON, lambda event: self.Close())
    btn_sizer.AddButton(cancel_btn)
    
    btn_sizer.Realize()
    
  def unlock(self):    
    try:
      f = open(self.path, 'rb')
      f.seek(0)
      hash_algorithm = HashAlgorithm(int.from_bytes(f.read(1), 'big'))
      f.close()
      hashed_password = hash(str(self.password_textctrl.GetValue()).encode(), hash_algorithm).to_bytes()
    
      decryption_key = hashed_password
      unlock(self.path, decryption_key)
    except Exception as e:
      wx.MessageBox(str(e), 'エラーが発生しました')
    finally: self.Close()
    
class ConfirmPasswordDialog(wx.Dialog):
  def __init__(self, hashed_password: bytes):
    self.hashed_password = hashed_password
    
    super().__init__(None, title='パスワードの確認', size=(300, 125))
    self.SetBackgroundColour('white')
    self.SetWindowStyle(wx.DEFAULT_FRAME_STYLE & ~(wx.RESIZE_BORDER | wx.MAXIMIZE_BOX))

    sizer = wx.BoxSizer(wx.VERTICAL)
    self.SetSizer(sizer)
    
    password_textctrl = wx.TextCtrl(self, style=wx.TE_PASSWORD)
    sizer.Add(password_textctrl, flag=wx.EXPAND | wx.ALL, border=10)
    
    btn_sizer = wx.StdDialogButtonSizer()
    sizer.Add(btn_sizer, flag=wx.EXPAND | wx.ALL, border=10)

    lock_btn = wx.Button(self, wx.ID_OK, label='OK')
    lock_btn.Bind(wx.EVT_BUTTON, lambda event: 
      self.EndModal(wx.ID_YES) if hash(str(password_textctrl.GetValue()).encode()).to_bytes() == self.hashed_password else self.EndModal(wx.ID_NO))
    lock_btn.SetDefault()
    btn_sizer.AddButton(lock_btn)
    
    cancel_btn = wx.Button(self, wx.ID_CANCEL, label='キャンセル')
    btn_sizer.AddButton(cancel_btn)
    
    btn_sizer.Realize()
    
if __name__ == '__main__':
  app = SimpleFileLock()
  app.MainLoop()
