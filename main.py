import hashlib
import os
import wx

class SimpleFileLock(wx.App):
  def OnInit(self):
    StartFrame().Show(True)
    return True
  
class StartFrame(wx.Frame):
  def __init__(self):
    super().__init__(None, title='Simple File Lock', size=(300, 200))
    self.SetBackgroundColour('white')
    self.SetWindowStyle(wx.DEFAULT_FRAME_STYLE & ~(wx.RESIZE_BORDER | wx.MAXIMIZE_BOX))
    
    select_file_button = wx.Button(self, label='ファイルを選択')
    select_file_button.Bind(wx.EVT_BUTTON, self.on_select_file_button_pressed)
    
  def on_select_file_button_pressed(self, event):
    dialog = wx.FileDialog(self, 'ファイルの選択')
    dialog.SetWindowStyle(wx.FD_OPEN | wx.FD_FILE_MUST_EXIST | wx.FD_MULTIPLE)
    dialog.SetWildcard('すべてのファイル(*.*)|*.*|SimpleFileLockファイル(*.sfl)|*.sfl|SimpleFileLock実行ファイル(*.runsfl)|*.runsfl')

    if dialog.ShowModal() == wx.ID_OK:
      file_open(dialog.GetPaths())
      
class LockFrame(wx.Frame):
  def __init__(self, name):
    super().__init__(None, title=name + 'をロック', size=(400, 150))
    self.SetBackgroundColour('white')
    self.SetWindowStyle(wx.DEFAULT_FRAME_STYLE & ~(wx.RESIZE_BORDER | wx.MAXIMIZE_BOX))
    
    panel = wx.Panel(self)
    top_sizer = wx.BoxSizer(wx.VERTICAL)
    panel.SetSizer(top_sizer)
    
    sizer = wx.GridBagSizer()
    top_sizer.Add(sizer, 1, flag=wx.EXPAND)

    sizer.Add(wx.StaticText(panel, label='パスワード', style=wx.TE_LEFT), (0, 1), flag=wx.EXPAND | wx.ALIGN_CENTER)
    password_textctrl = wx.TextCtrl(panel)
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
    hashed_password = hashlib.sha256(str(self.password_textctrl.GetValue()).encode()).digest()
    
    result = ConfirmPasswordDialog(hashed_password).ShowModal()
    if (result == wx.ID_CANCEL): self.Close()
    elif (result == wx.ID_NO): wx.MessageBox('パスワードが異なっています')
    
class ConfirmPasswordDialog(wx.Dialog):
  def __init__(self, hashed_password):
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
      self.EndModal(wx.ID_YES) if hashlib.sha256(str(password_textctrl.GetValue()).encode()).digest() == self.hashed_password else self.EndModal(wx.ID_NO))
    lock_btn.SetDefault()
    btn_sizer.AddButton(lock_btn)
    
    cancel_btn = wx.Button(self, wx.ID_CANCEL, label='キャンセル')
    btn_sizer.AddButton(cancel_btn)
    
    btn_sizer.Realize()

def file_open(paths: list[str]):
  lock_files = []
  unlock_files = []
  
  for path in paths:
    ext = os.path.splitext(path)[1]
    if ext == '.sfl': unlock_files.append(path)
    else: lock_files.append(path)
    
  if len(lock_files) == 1: LockFrame(os.path.basename(lock_files[0])).Show(True)
  elif len(lock_files) >= 2: LockFrame(str(len(lock_files)) + '個のファイル').Show(True)
    
if __name__ == '__main__':
  app = SimpleFileLock()
  app.MainLoop()
