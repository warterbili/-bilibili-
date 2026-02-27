"""
UIAutomator2 入门测试脚本
功能：连接手机，获取设备信息，演示基本操作
"""
import uiautomator2 as u2
import time

# ============ 1. 连接设备 ============
print("正在连接设备...")
d = u2.connect()  # 自动连接USB设备
print(f"设备信息: {d.info}")
print(f"屏幕尺寸: {d.window_size()}")
print()

# ============ 2. 获取当前App信息 ============
app_info = d.app_current()
print(f"当前App: {app_info}")
print()

# ============ 3. 截图保存 ============
# d.screenshot("screenshot_test.png")
# print("截图已保存: screenshot_test.png")

# ============ 4. 打开【设置】App 演示 ============
print("正在打开【设置】...")
d.app_start("com.android.settings")
time.sleep(2)

# 打印当前页面的UI层级（类似浏览器的DOM）
print("当前页面元素:")
print(d.dump_hierarchy()[:2000])  # 只打印前2000字符，避免刷屏
print("...(截断)")
print()

# ============ 5. 元素查找与操作演示 ============

# 方式1: 通过文字查找
if d(text="Network & internet").exists(timeout=3):
    print("找到【Network & internet】，点击它")
    d(text="Network & internet").click()
    time.sleep(2)
    d.press("back")  # 返回
    time.sleep(1)

# 方式2: 通过resourceId查找
# d(resourceId="com.android.settings:id/xxx").click()

# 方式3: 通过className查找
# d(className="android.widget.TextView").click()

# ============ 6. 模拟手势 ============
print("演示滑动操作（向上滑动）...")
d.swipe_ext("up", scale=0.5)  # 向上滑半屏
time.sleep(1)

print("演示滑动操作（向下滑动）...")
d.swipe_ext("down", scale=0.5)
time.sleep(1)

# ============ 7. 模拟按键 ============
print("按Home键回到桌面...")
d.press("home")
time.sleep(1)

# ============ 8. 获取Toast消息（如果有的话） ============
# toast = d.toast.get_message(timeout=3)
# print(f"Toast: {toast}")

print()
print("===== 测试完成 =====")
print()
print("常用API速查:")
print("  d(text='xxx').click()       # 按文字点击")
print("  d(resourceId='xxx').click() # 按ID点击")
print("  d(text='xxx').set_text('y') # 输入文字")
print("  d(text='xxx').exists        # 判断元素存在")
print("  d.press('back')             # 返回键")
print("  d.press('home')             # Home键")
print("  d.screenshot('x.png')       # 截图")
print("  d.app_start('包名')         # 启动App")
print("  d.app_stop('包名')          # 关闭App")
print("  d.swipe_ext('up')           # 滑动")
print("  d.dump_hierarchy()          # 获取UI树(XML)")
