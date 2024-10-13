
def big_P_Q():                  #产生两个大素数
    flag = 0
    while not flag:
        p = random.randrange(10**10,10**11)

        if charge_sushu_1(p) and _ack(2,p):

            q = random.randrange(p,10**11)
            if charge_sushu_1(q) and p != q and _ack(2,q):
                flag = 1
    return p,q