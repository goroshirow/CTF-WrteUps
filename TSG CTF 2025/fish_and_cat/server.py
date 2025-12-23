import os
import random

FLAG = os.getenv("FLAG", "TSGCTF{REDACTED}")

loop_num = 15000

def fish_exec(code, input_num):
    pointer = [0, 0]
    speed = [0, 1]
    stack = []
    input_counter = 0
    output_buffer = []
    def move():
        i, j = pointer
        if speed[0] != 0:
            i = (i + speed[0]) % len(code)
            while j >= len(code[i]):
                i = (i + speed[0]) % len(code)
        if speed[1] != 0:
            j = (j + speed[1]) % len(code[i])
        pointer[0], pointer[1] = i, j
    for _ in range(loop_num):
        ci, cj = pointer
        # --- デバッグ表示用コード (ここから) ---
        import os
        # 画面を見やすくするために毎回クリアする（不要ならコメントアウトしてください）
        os.system('cls' if os.name == 'nt' else 'clear') 
        
        
        print(f"\n=== Step: {_} | Pointer: {pointer} | Speed: {speed} ===")
        # === 修正箇所: ここに Key と Output Buffer の表示を追加 ===
        print(f"Key (input_num): {input_num}") 
        print(f"Output Buffer: {output_buffer}")

        print(f"Stack: {stack}")
        print("Grid:")
        for r, row in enumerate(code):
            line_str = ""
            for c, val in enumerate(row):
                # 数値を文字に変換（表示できない文字は '?' にする）
                char = chr(val)
                if not char.isprintable() and char != ' ':
                    char = '?'
                
                # 現在のポインタ位置を強調表示 (例: [>])
                if r == pointer[0] and c == pointer[1]:
                    line_str += f"[{char}]"
                else:
                    line_str += f" {char} "
            print(line_str)
        import time
        time.sleep(0.2) # 高速すぎて見えない場合はここで待機時間を調整
        # --- デバッグ表示用コード (ここまで) ---
        match code[ci][cj]:
            case 33: # !
                move()
            case 34: # "
                # TODO
                0
            case 35: # #
                speed[0] *= -1
                speed[1] *= -1
            case 36: # $
                assert len(stack) >= 2
                stack[-1], stack[-2] = stack[-2], stack[-1]
            case 37: # %
                assert len(stack) >= 2
                x = stack.pop()
                y = stack.pop()
                assert x != 0
                stack.append(y % x)
            case 38: # &
                # TODO
                0
            case 39: # '
                # TODO
                0
            case 40: # (
                assert len(stack) >= 2
                x = stack.pop()
                y = stack.pop()
                stack.append(int(y < x))
            case 41: # )
                assert len(stack) >= 2
                x = stack.pop()
                y = stack.pop()
                stack.append(int(y > x))
            case 42: # *
                assert len(stack) >= 2
                x = stack.pop()
                y = stack.pop()
                stack.append(y * x)
            case 43: # +
                assert len(stack) >= 2
                x = stack.pop()
                y = stack.pop()
                stack.append(y + x)
            case 44: # ,
                assert len(stack) >= 2
                x = stack.pop()
                y = stack.pop()
                assert x != 0
                stack.append(y // x)
            case 45: # -
                assert len(stack) >= 2
                x = stack.pop()
                y = stack.pop()
                stack.append(y - x)
            case 46: # .
                assert len(stack) >= 2
                x = stack.pop()
                y = stack.pop()
                assert 0 <= x < len(code) and 0 <= y < len(code[x])
                pointer = [x, y]
            case 47: # /
                speed[0], speed[1] = -speed[1], -speed[0]
            case 48: # 0
                stack.append(0)
            case 49: # 1
                stack.append(1)
            case 50: # 2
                stack.append(2)
            case 51: # 3
                stack.append(3)
            case 52: # 4
                stack.append(4)
            case 53: # 5
                stack.append(5)
            case 54: # 6
                stack.append(6)
            case 55: # 7
                stack.append(7)
            case 56: # 8
                stack.append(8)
            case 57: # 9
                stack.append(9)
            case 58: # :
                assert len(stack) >= 1
                stack.append(stack[-1])
            case 59: # ;
                break
            case 60: # <
                speed = [0, -1]
            case 61: # =
                assert len(stack) >= 2
                x = stack.pop()
                y = stack.pop()
                stack.append(int(y == x))
            case 62: # >
                speed = [0, 1]
            case 63: # ?
                assert len(stack) >= 1
                x = stack.pop()
                if x == 0:
                    move()
            case 64: # @
                assert len(stack) >= 3
                stack[-1], stack[-2], stack[-3] = stack[-2], stack[-3], stack[-1]
            case 91: # [
                # TODO
                0
            case 92: # \
                speed[0], speed[1] = speed[1], speed[0]
            case 93: # ]
                # TODO
                0
            case 94: # ^
                speed = [-1, 0]
            case 95: # _
                if speed[0] != 0:
                    speed[0] *= -1
            case 97: # a
                stack.append(10)
            case 98: # b
                stack.append(11)
            case 99: # c
                stack.append(12)
            case 100: # d
                stack.append(13)
            case 101: # e
                stack.append(14)
            case 102: # f
                stack.append(15)
            case 103: # g
                assert len(stack) >= 2
                x = stack.pop()
                y = stack.pop()
                stack.append(code[x][y] if 0 <= x < len(code) and 0 <= y < len(code[x]) else 0)
            case 105: # i
                if input_counter < len(input_num):
                    stack.append(input_num[input_counter])
                    input_counter += 1
                else:
                    stack.append(-1)
            case 108: # l
                stack.append(len(stack))
            case 110: # n
                assert len(stack) >= 1
                output_buffer.append(stack.pop())
            case 111: # o
                # TODO
                0
            case 112: # p
                assert len(stack) >= 3
                x = stack.pop()
                y = stack.pop()
                z = stack.pop()
                assert 0 <= x < len(code) and 0 <= y < len(code[x])
                code[x][y] = z
            case 114: # r
                stack = stack[::-1]
            case 118: # v
                speed = [1, 0]
            case 120: # x
                speed = ([0, 1], [1, 0], [0, -1], [-1, 0])[random.randrange(4)]
            case 123: # {
                if len(stack) >= 1:
                    x, *stack = stack
                    stack.append(x)
            case 124: # |
                if speed[1] != 0:
                    speed[1] *= -1
            case 125: # }
                if len(stack) >= 1:
                    x = stack.pop()
                    stack = [x] + stack
            case 126: # ~
                assert len(stack) >= 1
                stack.pop()
            case _:
                # do nothing
                0
        move()
    print(f"\n=== Final State ===")
    print(f"output_buffer: {output_buffer}")
    return output_buffer

def security_check(code):
    return 1 <= len(code[0]) <= 125 and all(ord('a') <= number <= ord('z') for number in code[0])

print('It looks like the fish wants to eat the cat...')
print('Help it out !')
print('(enter your code >)')

try:
    code = [list(map(ord, input()))]
except:
    print('The fish dried out...')
    exit()

if not security_check(code):
    print('The cat ran away...')
    exit()

for _ in range(32):
    key_len = random.randrange(1, 100)
    key = [random.randrange(1, 10) for _ in range(key_len)]
    try:
        cat_key = fish_exec(code, key)
    except:
        print('something smells fishy...')
        print(f'Expected key: {key}')
        break
    if key != cat_key:
        print('The cat ate the fish...')
        print(f'Expected key: {key}')
        break
    print("success check with key length", key_len)
else:
    print('The fish actually managed to eat the cat!!!')
    print(FLAG)