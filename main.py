import wx

class SimpleFileLock(wx.App):
  def OnInit(self):
    StartFrame().Show(True)
    return True
  
class StartFrame(wx.Frame):
  def __init__(self):
    super().__init__(None)
    self.SetTitle("Simple File Lock")
    self.SetSize(300, 200)
    self.SetBackgroundColour("white")
    self.SetWindowStyle(wx.DEFAULT_FRAME_STYLE & ~(wx.RESIZE_BORDER | wx.MAXIMIZE_BOX))
    
    select_file_button = wx.Button(self, label="ファイルを選択")
    select_file_button.Bind(wx.EVT_BUTTON, self.on_select_file_button_pressed)
    
  def on_select_file_button_pressed(self, event):
    pass
    
if __name__ == "__main__":
  app = SimpleFileLock()
  app.MainLoop()
