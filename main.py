import subprocess
import tempfile
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto import Random
from enum import Enum, Flag, auto
import hashlib
import os
import re
from typing import Callable
import wx
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

editing_files: dict[str, str] = {}

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
    
class _FileEditEventHandler(FileSystemEventHandler):
  def __init__(self): super().__init__()
  
  def on_modified(self, event):
    path = event.src_path
    if path in editing_files:
      lock(path, editing_files[path][0], editing_files[path][1])
  
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
    
def lock(path: str, newpath:str, encryption_key: bytes):
  confirm_meta = encryption_key
  
  with open(path, 'rb') as org, open(newpath, 'wb') as locked:
    (cipher, decryption_meta) = encrypt(len(confirm_meta).to_bytes(2, 'big') + confirm_meta + org.read(), encryption_key)
    locked.write(DEFALUT_HASH_ALGORITHM.value.to_bytes(1, 'big') + DEFAULT_ENCRYPTION_ALGORITHM.value.to_bytes(1, 'big') + \
      len(decryption_meta).to_bytes(2, 'big') + decryption_meta + cipher)

def unlock(path: str, newpath: str, decryption_key: bytes):
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
      return True
    else:
      wx.MessageBox('パスワードが間違っています', 'エラー')
      return False
    
def open_file(paths: list[str]):
  unencrypted_files = []
  for path in paths:
    if os.path.isfile(path):
      if os.path.splitext(path)[1] == '.sfl': UnlockFrame('edit', path).Show(True)
      else: unencrypted_files.append(path)
  if len(unencrypted_files) >= 1: LockFrame(unencrypted_files).Show(True)

class SimpleFileLock(wx.App):
  def OnInit(self):
    StartFrame().Show(True)
    return True
  
class StartFrame(wx.Frame):
  def __init__(self):
    super().__init__(None, title='Simple File Lock', size=(300, 250))
    self.SetBackgroundColour('white')
    self.SetWindowStyle(wx.DEFAULT_FRAME_STYLE & ~(wx.RESIZE_BORDER | wx.MAXIMIZE_BOX))
    self.SetDropTarget(FileDropTarget())

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
        UnlockFrame('unlock', path).Show(True)
        
  def on_edit_file_button_pressed(self, event):
    dialog = wx.FileDialog(self, 'ファイルの選択')
    dialog.SetWindowStyle(wx.FD_OPEN | wx.FD_FILE_MUST_EXIST | wx.FD_MULTIPLE)
    dialog.SetWildcard('SimpleFileLockファイル(*.sfl)|*.sfl')

    if dialog.ShowModal() == wx.ID_OK:
      paths = dialog.GetPaths()
      for path in paths:
        UnlockFrame('edit', path).Show(True)
        
class FileDropTarget(wx.FileDropTarget):
  def __init__(self): super().__init__()
  
  def OnDropFiles(self, x, y, filenames):
    open_file(filenames)
    return True
      
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
          lock(path, re.sub(r'\.runsfl$', '.sfl', path) if path.endswith('.runsfl') else path + '.sfl', encryption_key)
      except Exception as e:
        wx.MessageBox(str(e), 'エラーが発生しました')
      finally: self.Close()
      
class UnlockFrame(wx.Frame):
  def __init__(self, type, path: str):
    self.path = path
    
    name = os.path.basename(path)
    super().__init__(None, title=name + 'を' + ('アンロック' if type == 'unlock' else '編集' if type == 'edit' else ''), size=(400, 150))
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
    lock_btn.Bind(wx.EVT_BUTTON, lambda event: self.unlock() if type == 'unlock' else self.edit() if type == 'edit' else None)
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
      unlock(self.path, re.sub(r'\.sfl$', '', self.path), decryption_key)
    except Exception as e:
      wx.MessageBox(str(e), 'エラーが発生しました')
    finally: self.Close()
    
  def edit(self):
    try:
      f = open(self.path, 'rb')
      f.seek(0)
      hash_algorithm = HashAlgorithm(int.from_bytes(f.read(1), 'big'))
      f.close()
      hashed_password = hash(str(self.password_textctrl.GetValue()).encode(), hash_algorithm).to_bytes()
    
      (name, ext) = os.path.splitext(os.path.splitext(os.path.basename(self.path))[0])
      tempfile_path = tempfile.NamedTemporaryFile(prefix=name + '_', suffix=ext).name
    
      decryption_key = hashed_password
      if unlock(self.path, tempfile_path, decryption_key):
        EditFrame(self.path, tempfile_path, decryption_key).Show(True)
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
    
class EditFrame(wx.Frame):
  def __init__(self, file_path: str, tempfile_path: str, encryption_key: str):
    self.tempfile_path = tempfile_path
    
    super().__init__(None, title=os.path.basename(file_path) + 'の編集', size=(280, 70))
    self.SetBackgroundColour('white')
    self.SetWindowStyle(wx.DEFAULT_FRAME_STYLE & ~(wx.RESIZE_BORDER | wx.MAXIMIZE_BOX))
    self.Bind(wx.EVT_CLOSE, self.on_close)
    
    panel = wx.Panel(self)
    sizer = wx.BoxSizer(wx.HORIZONTAL)
    panel.SetSizer(sizer)
    
    open_btn = wx.Button(panel, wx.ID_OK, label='既定のプログラムで開く')
    open_btn.Bind(wx.EVT_BUTTON, lambda event: subprocess.Popen(['start', tempfile_path], shell=True))
    sizer.Add(open_btn, proportion=1, flag=wx.EXPAND | wx.ALL, border=5)
    
    end_btn = wx.Button(panel, wx.ID_CLOSE, label='編集を終了')
    end_btn.Bind(wx.EVT_BUTTON, lambda event: self.Close())
    sizer.Add(end_btn, proportion=1, flag=wx.EXPAND | wx.ALL, border=5)
    
    editing_files[tempfile_path] = (file_path, encryption_key)
    
  def on_close(self, event):
    editing_files.pop(self.tempfile_path)
    os.remove(self.tempfile_path)
    self.Destroy()
    
if __name__ == '__main__':
  try:
    observer = Observer()
    observer.schedule(_FileEditEventHandler(), tempfile.gettempdir(), recursive=True)
    observer.start()
    
    app = SimpleFileLock()
    app.MainLoop()
    
    observer.stop()
    observer.join()
  finally:
    for i in editing_files.keys(): os.remove(i)
