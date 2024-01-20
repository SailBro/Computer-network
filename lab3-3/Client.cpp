#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS 1

#include <WinSock2.h>
#include <thread>
#include <fstream>
#include <cmath>
#include<time.h>
#include<fstream>
#include<iostream>
#include<windows.h>
#include <mutex>

using namespace std;
#pragma comment(lib,"ws2_32.lib")
#define WAITING_MAX 100
#define DATA_LEN_MAX 15000
#define DATA_ALL 90000000
#define SYN 0
#define ACK 1
#define SYN_ACK 2
#define OVER 3
#define FIN 4
#define FIN_ACK 5
#define SEQ 6

/**** 一些常量定义****/
// IP（32位）和端口（16位）
const uint32_t SOURCE_IP = 2130706433;
const uint32_t DESTINATION_IP = 2130706433;
const uint16_t SOURCE_PORT = 8888;
const uint16_t DESTINATION_PORT = 8887;

/**** 全局变量定义****/
// 套接字
SOCKET ClientSocket;
// 地址
SOCKADDR_IN ServerAddress;
SOCKADDR_IN ClientAddress;
int ServerAddLen;
int ClientAddLen;
WSADATA wsaData;
double Loss = 0.02;
string figName;
/**** 下面是GBN新增变量 ****/
// 发送线程
int WindowSize = 8;
int BasePointer = 1;
int NextSeqPointer = 1;
// 接收线程
// int RecvAck = -1;
// bool RecvFlag = 0;
// 重发线程
// bool ReSendFlag = 0;
// int StartSeq = -1;
// int EndSeq = -1;

// 延时
int timmer = 0;

mutex mtx;  // 互斥锁

unsigned long long int TempByte = 0;// 已经传输过去的字节数量
int tally; // 发送的数据包的个数
unsigned long long int ByteNum = 0;
int CloseFlag = 0;

// 存储data的数组（char*类型，和缓冲区一样）
char* SendData;

/*** 3-3新增 ***/
int WaitAckBuff[50];// 窗口中已发送，等待被确认的ack（存的就是ack）
int WaitBeginIndex = 0;// 等待的最小ack（队首）
int WaitEndIndex = 0;// 下一个可存放的位置（队尾）
// int WaitNum = 0;// 等待被确认的ack的个数
// 
class TimerClass {
public:
    bool flag;
    clock_t timer;
    TimerClass() {
        flag = 1;// 一开始生成就开始计时的
        timer = clock();// 开始计时
    }
    void open() {
        flag = 1;
    }
    void close() {
        flag = 0;
    }
    void set() {
        // 重启
        flag = 1;
        timer = clock();// 重新开始计时
    }
};
// 计时器数组
TimerClass* Timers[50];

class PseudoHeader;// 伪首部

// 数据头格式
class Header {
public:
    uint16_t SourcePort; // 源端口号
    uint16_t DestPort; // 目的端口号
    uint16_t len; // 长度
    uint16_t Checksum; // 校验和
    int ack; // 确认号
    int seq; // 序列号
    int flag; // 标志位
    int fin; // 结束标志

    Header() {
        SourcePort = SOURCE_PORT;
        DestPort = DESTINATION_PORT;
        len = Checksum = 0;
        ack = seq = flag = fin = 0;
    }

    void reset() {
        SourcePort = SOURCE_PORT;
        DestPort = DESTINATION_PORT;
        len = Checksum = 0;
        ack = seq = flag = fin = 0;
    }

    // 重置端口
    void resetPort() {
        SourcePort = SOURCE_PORT;
        DestPort = DESTINATION_PORT;
    }

    // 端口取反
    void reservePort() {
        SourcePort = DESTINATION_PORT;
        DestPort = SOURCE_PORT;
    }

    void print() {

        if (flag == 0)
            cout << "flag:SYN  " << "Checksum  " << Checksum << endl;
        else if (flag == ACK)
            cout << "flag:ACK  " << "ack:" << ack << "  Checksum  " << Checksum << endl;
        else if (flag == SYN_ACK)
            cout << "flag:SYN,ACK  " << "ack:" << ack << "  Checksum  " << Checksum << endl;
        else if (flag == OVER)
            cout << "flag:OVER  " << endl;
        else if (flag == FIN)
            cout << "flag:FIN  fin:" << fin << "  Checksum  " << Checksum << endl;
        else if (flag == FIN_ACK)
            cout << "flag:FIN,ACK  fin:" << fin << "  ack:" << ack << "  Checksum  " << Checksum << endl;
        else if (flag == SEQ)
            cout << "flag:SEQ  " << "seq:" << seq << "  Checksum  " << Checksum << endl;
    }


};

// 伪首部，用于UDP校验
class PseudoHeader {
public:
    uint32_t SourceIp; // 源IP地址
    uint32_t DestIp; // 目的IP地址
    uint8_t Protovol; // 协议
    uint16_t len;// 长度
    PseudoHeader() {
        SourceIp = SOURCE_IP;
        DestIp = DESTINATION_IP;
        Protovol = len = 0;
    }

    // IP取反
    void reserveIP() {
        SourceIp = DESTINATION_IP;
        DestIp = SOURCE_IP;
    }

    // 计算给定的数据头的校验和
    uint16_t Cal_Checksum(Header* head) {
        // return 0;
        head->resetPort();
        int size = sizeof(*head) + sizeof(SourceIp) + sizeof(DestIp);// 32位+32位
        // int size = sizeof(*head);
        // cout << size << endl;
        int count = size / 2; // 16位==2字节
        u_short* buf = (u_short*)malloc(size);
        // 先全部清0
        memset(buf, 0, size);
        memcpy(buf, head, sizeof(*head));
        // cout << buf << " ";
        // memcpy(buf + sizeof(*head), &SourceIp, sizeof(SourceIp));
        // cout << buf << " ";
        // memcpy(buf + sizeof(*head) + sizeof(SourceIp), &DestIp, sizeof(DestIp));
        // cout << buf << " " << endl;
        u_long res = 0;
        for (int i = 0;i < count;i++) {
            // cout << res << " ";
            res += *buf++;
            // 溢出时需要+1
            if (res & 0xffff0000) {
                // 高16位不为0
                res &= 0xffff;
                res++;
            }
        }
        return ~(res & 0xffff);// 保留低16位
    }
};

void init() {
    // 初始化套接字
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    //ioctlsocket(ClientSocket, FIONBIO, &unblockmode);

    // 设置服务器端地址
    ServerAddress.sin_family = AF_INET;
    ServerAddress.sin_addr.s_addr = htonl(2130706433);
    ServerAddress.sin_port = htons(8887);

    // 设置客户端地址
    ClientAddress.sin_family = AF_INET;
    ClientAddress.sin_addr.s_addr = htonl(2130706433);
    ClientAddress.sin_port = htons(8888);

    // 绑定客户端
    ClientSocket = socket(AF_INET, SOCK_DGRAM, 0);
    int bind_res = bind(ClientSocket, (sockaddr*)&ClientAddress, sizeof(ClientAddress));
    if (bind_res == SOCKET_ERROR) {
        cout << "client: bind failed." << endl;
    }

    unsigned long on = 1;
    ioctlsocket(ClientSocket, FIONBIO, &on);

    ClientAddLen = sizeof(ClientAddress);
    ServerAddLen = sizeof(ServerAddress);

    cout << "客户端端初始化完成！" << endl;

}

// 辅助函数：差错检验
bool CheckError(Header* head, int len) {
    // return true;
    // 在这里生成伪首部，计算校验位
    PseudoHeader* Phead = new PseudoHeader();
    // IP取反
    Phead->reserveIP();
    // 把head的端口取反
    head->reservePort();
    if (head->Checksum == Phead->Cal_Checksum(head))
        return true;// 通过检验
    // cout << "ERROR:" << head->Checksum << "," << Phead->Cal_Checksum(head) << endl;
    // head->print();
    return true;
}

int ClientConnect() {
    // 主要完成发起1、3请求


    /**** 发起第一次握手请求 ****/
    // 新建数据头和两个缓冲区
    Header header;
    header.flag = SEQ;
    char* RecvBuff = new char[1000];
    char* SendBuff = new char[1000];
    // cout << sizeof(SendBuff) << endl;
    // cout << "客户端开始等待连接......" << endl;

    // 设置数据头信息
    header.flag = SYN;
    // 生成伪首部，计算校验和
    PseudoHeader* Phead = new PseudoHeader();
    header.Checksum = Phead->Cal_Checksum(&header);

    // header存到缓冲区，准备发送
    // cout << "[client]:第一次握手消息发送ing......" << endl;
    memcpy(SendBuff, &header, sizeof(header));
    // cout << sizeof(header)<<" "<<sizeof(SendBuff) << endl;
    // header.print();
    while (sendto(ClientSocket, SendBuff, sizeof(header), 0, (SOCKADDR*)&ServerAddress, ServerAddLen) == -1) {
        // cout << "第一次握手发送数据失败！" << endl;
        // cout << "1";
        cout << WSAGetLastError() << endl;
    }
    cout << "[client]:第一次握手发送数据成功！" << endl;
    header.print();


    /**** 接收第二次握手消息 ****/

    // 记得开始计时
    header.reset();
    clock_t time = clock();
    while (true) {
        int recv_len = recvfrom(ClientSocket, RecvBuff, sizeof(header), 0, (SOCKADDR*)&ServerAddress, &ServerAddLen);
        // 还是先判断是否超时
        if (clock() - time > WAITING_MAX) {
            // 超时须重发
            // cout << "第一或二次握手消息传输超时！" << endl;
            // cout << "正在重发第一次握手消息......" << endl;
            int send_len = sendto(ClientSocket, SendBuff, sizeof(header), 0, (SOCKADDR*)&ServerAddress, ServerAddLen);
            if (send_len < 0) {
                cout << "第一次握手发送数据失败！" << endl;
                return -1;
            }
            cout << "[client]:第一次握手消息发送成功！" << endl;
            header.print();
            // ！！！！重新计时
            time = clock();
            continue; // 然后继续等待接收第二次握手的消息
        }
        // 没有超时
        if (recv_len < 0) {
            // cout << " 第二次握手消息接收ing......" << endl;
            continue;
        }
        memcpy(&header, RecvBuff, sizeof(header));
        // 差错检验
        if (header.flag == SYN_ACK && header.ack == 1 && CheckError(&header, sizeof(header)) == true) {
            cout << "[client]:第二次握手消息接收成功！" << endl;
            break;// 跳出循环
        }
        // cout << "第二次握手数据检验不通过！" << endl;
        // cout << "正在重新接收第二次握手消息......" << endl;
    }


    /**** 发起第三次握手 ****/
    // 设置数据头信息
    header.reset();
    header.flag = ACK;
    header.ack = 1;// 接收到了第二次握手
    // 生成伪首部，计算校验和
    header.Checksum = Phead->Cal_Checksum(&header);

    // header存到缓冲区，准备发送
    cout << "[client]:第三次握手消息发送成功！" << endl;
    header.print();
    memcpy(SendBuff, &header, sizeof(header));
    while (sendto(ClientSocket, SendBuff, sizeof(header), 0, (SOCKADDR*)&ServerAddress, ServerAddLen) == false) {
        // cout << "第三次握手发送数据失败！" << endl;
    }

    // cout << "[client]:第三次握手成功！" << endl;
    cout << "[client]:开始传输数据......" << endl;


    return 0;
}

DWORD WINAPI SendMessageThread(void* param) {

    // 先建立数据头部和缓冲区
    Header header;
    PseudoHeader* Phead = new PseudoHeader();
    header.flag = SEQ;
    // 一开始seq和ack都为0
    char* SendBuff = new char[sizeof(header) + DATA_LEN_MAX];
    // data清空
    SendData = new char[DATA_ALL];

    /**** 加载数据 ****/
    // 打开文件
    ifstream is("file//" + figName, ifstream::binary);

    // 和server端不同的是不知道文件大小，只能一个一个读入
    unsigned char temp = is.get();
    while (is) {
        SendData[ByteNum++] = temp;
        temp = is.get();
    }
    cout << "[client]:文件已经成功读入，大小为" << ByteNum << "字节" << endl;
    is.close();


    /**** 传输数据前的准备 ****/
    // 分组号0~2^k-1(k为WindowSize)
    // 先计算一下要传多少次，然后设置丢包率
    tally = ByteNum / DATA_LEN_MAX + 1;
    cout << "[client]:文件即将拆分成" << tally << "个包进行传输" << endl;
    int loss_pck = 1 / Loss;
    int loss = 0;
    clock_t begin = clock();
    // 传输的线程中，发送的报文标志位固定为SEQ
    header.flag = SEQ;

    while (true) {
        /*if ((clock() - begin) % 5000 == 0) {
            for (int i = 0;i < WindowSize;i++) {
                cout << WaitAckBuff[i];
                if (Timers[i] != nullptr)
                    cout << "(" << clock() - Timers[i]->timer << ") ";
            }
        }*/

        mtx.lock();
        int tempBase = BasePointer;
        int tempNext = NextSeqPointer;
        mtx.unlock();

        if (tempNext >= tempBase + WindowSize) {
            // cout<<tempNext<< "发送被拒绝了（" << tempBase<<" :"<< tempBase + WindowSize<<endl;
            //cout << tempBase + WindowSize << " ";
            continue;// 拒绝
        }
        if (tempNext == tally + 1) {
            if (tempBase == tally + 1)
                break;
            else
                continue;
        }

        // 正常发送
        // 只要在窗口内部就可以发！！！ （前面已经判断过了）

        // 每次进循环需要先将报文数据打包至缓冲区
        header.seq = NextSeqPointer; // 发送下个Seq
        header.Checksum = Phead->Cal_Checksum(&header);
        // 最后一次发剩下的
        int Templen = (NextSeqPointer == tally) ? ByteNum - TempByte : DATA_LEN_MAX;
        // 先把数据报头放入缓冲区，再放入Data
        memcpy(SendBuff, &header, sizeof(header));
        memcpy(SendBuff + sizeof(header), SendData + TempByte, Templen);

        // 窗口挪动
        // BasePointer += 1;
        // 每count_pck个丢个包
        if (NextSeqPointer % loss_pck == 2) {
            loss++;
            cout << "[client]:分组" << NextSeqPointer << "丢包[" << NextSeqPointer << "]测试......" << " 窗口：" << BasePointer << "-" << BasePointer+WindowSize << endl;
            
        }
        else {// 正常发
            while (sendto(ClientSocket, SendBuff, sizeof(header) + Templen, 0, (SOCKADDR*)&ServerAddress, ServerAddLen) < 0)
                ;//cout << WSAGetLastError() << endl;
            cout << "[client]:成功发送分组" << NextSeqPointer << "的数据包[" << NextSeqPointer << "]！" << " 窗口：" << BasePointer << "-" << BasePointer + WindowSize << endl;
            header.print();
        }

        TempByte += Templen;// recv和resend都用不上
        cout << TempByte << endl;

        // mtx.lock();// 这里开始锁（WaitAckBuff同步）
        // 需要将刚发出的加入WaitBuff中等待确认
        mtx.lock();
        WaitAckBuff[WaitEndIndex] = NextSeqPointer;
        Timers[WaitEndIndex]->set();// 和seq一样的位置下标
        WaitEndIndex++;
        
        WaitEndIndex = WaitEndIndex >= WindowSize ? WaitEndIndex - WindowSize : WaitEndIndex;// 确保下一次能用

        NextSeqPointer++; // 发送成功就+1

        mtx.unlock();


        // 接收消息在另一个线程里面处理
        Sleep(timmer);
    }

    // 发送over之前还是需要判断一下有没有全部接收到


    // 发送结束的报文OVER=1
    header.reset();
    header.seq = NextSeqPointer;// 还是需要下一个分组来发
    header.flag = OVER;
    header.Checksum = Phead->Cal_Checksum(&header);
    memcpy(SendBuff, &header, sizeof(header));
    while (sendto(ClientSocket, SendBuff, sizeof(header), 0, (SOCKADDR*)&ServerAddress, ServerAddLen) < 0)
        ;

    // 发送端计算延时和吞吐率
    clock_t time_total = clock() - begin;
    double seed = (double)ByteNum / time_total;

    cout << "/************************************************************/" << endl;
    cout << "[client]:本次传输共发送" << ByteNum << "个字节，" << tally << "个数据包" << endl;
    cout << "    耗时:" << time_total << "ms" << endl;
    cout << "    吞吐率:" << seed << " Byte / ms" << endl;
    cout << "    丢包率:" << (double)loss / tally << endl;


    cout << "[client]:传输关闭......" << endl;
    cout << "/************************************************************/" << endl;

    return 0;
}

DWORD WINAPI RecvMessageThread(void* param) {

    // 建立头部和缓冲区
    Header header;
    PseudoHeader* Phead = new PseudoHeader();
    header.flag = ACK;
    char* RecvBuff = new char[sizeof(header)];
    int WaitBuff[50];

    // 在这个线程里一直接收并更新RecvAck就行
    while (true) {
        if (CloseFlag) {
            break;
        }
        int recv_len = recvfrom(ClientSocket, RecvBuff, sizeof(header), 0, (SOCKADDR*)&ServerAddress, &ServerAddLen);
        if (recv_len < 0 || CheckError(&header, sizeof(header)) == false)
            continue;
        // 接收到了就更新BasePointer
        memcpy(&header, RecvBuff, sizeof(header));
        cout << "接收到ack:" << header.ack << endl;
        // 累计确认
        // 判断收到的Ack所在范围
        mtx.lock();
        // 也缓存一份waitackbuff
        for (int i = 0;i < WindowSize;i++)
            WaitBuff[i] = WaitAckBuff[i];
        mtx.unlock();

        if (header.ack < BasePointer || header.ack >= BasePointer + WindowSize) {// 超出窗口界限的不处理
            cout << "接收ack" << header.ack << "超出窗口范围" << BasePointer << "," << BasePointer + WindowSize << endl;
            continue;
        }
        
        // cout << "接收到ack:" << header.ack << endl;

        // 在范围内的话就将当前ack标记为已经接收
        // 如果是base的话，就确认并开始滑动窗口
        if (header.ack == BasePointer) {
            // 加强判断：肯定是第一个
            // cout << WaitBuff[WaitBeginIndex] << endl;
            while (WaitBuff[WaitBeginIndex] != header.ack) {
                // 更新一下
                
                mtx.lock();
                // cout << "这了" << WaitBuff[WaitBeginIndex] << endl;
                WaitBuff[WaitBeginIndex] = WaitAckBuff[WaitBeginIndex];
                mtx.unlock();
            }
            BasePointer = header.ack + 1;// 期待接收的ACK+1
            // 记得数组中设置为-1
            // 要把对应的计时器也关掉哦
            mtx.lock();
            Timers[WaitBeginIndex]->close();
            WaitAckBuff[WaitBeginIndex++] = -1;
            WaitBeginIndex = WaitBeginIndex >= WindowSize ? WaitBeginIndex - WindowSize : WaitBeginIndex;
            mtx.unlock();
            // WaitNum--;
            /*else {
                cout << "something must be wrong!" << endl;
                cout << BasePointer<<" "<<header.ack<<" "<<WaitAckBuff[WaitBeginIndex] << endl;
            }*/
            // 确定下一个基序号：基序号为下一个未确认分组的序号
            int tempIndex = WaitBeginIndex;

            // while (true) {
            mtx.lock();
            int next = NextSeqPointer;
            int tempbase = WaitAckBuff[tempIndex];
            int tempN = 0;
            int indexRes = WaitEndIndex;// 如果没有未发送的了，begin和end保持一致就行
            while (tempN<=WindowSize) {
                if (WaitAckBuff[tempIndex] != -1) {
                    indexRes = tempIndex;
                    break;
                }
                tempIndex++;
                tempIndex = tempIndex >= WindowSize ? tempIndex - WindowSize : tempIndex;
                tempN++;
            }
            // base挪一下就行
            WaitBeginIndex = indexRes;
            // 若没有未发送的，则指向next就行
            if (WaitBeginIndex == WaitEndIndex)
                BasePointer = NextSeqPointer;
            else// 有未发送的，直接指向它
                BasePointer = WaitAckBuff[indexRes];

            mtx.unlock();
            
        }
        else {
            // 如果>base，则需要遍历找
            int tempIndex = WaitBeginIndex;
            int whileNum = 0;
            bool continueFlag = 0;
            while (true) {// 如果没更新也会等到更新就找到了
                whileNum++;
                if (whileNum > WindowSize + 1) {
                    // 重新复制一份
                    mtx.lock();
                    // 也缓存一份waitackbuff
                    for (int i = 0;i < WindowSize;i++)
                        WaitBuff[i] = WaitAckBuff[i];
                    mtx.unlock();
                }
                int tempSeq = WaitBuff[tempIndex];
                if (tempSeq == header.ack)
                    break;
                tempIndex++;
                tempIndex = tempIndex >= WindowSize ? tempIndex - WindowSize : tempIndex;
                // cout << tempIndex << " " << WaitBuff[tempIndex];
            }
            // 肯定会找见，然后只需要设为-1，个数减去1就行
            mtx.lock();
            WaitAckBuff[tempIndex] = -1;
            mtx.unlock();
            // 计时器关掉
            Timers[tempIndex]->close();
            // WaitNum--;
            // base还是不变
        }
        
        /*if (BasePointer == NextSeqPointer)
            TimeFlag = 0;// 关掉计时器
        else {
            TimeFlag = 1;// 开启计时器并更新
            Timer = clock();
        }*/

        // 和上面的思路差不多
        // TODO：可能得在resen那里做？？
    }

    return 0;
}

DWORD WINAPI SR_ReSendMessageThread(void* param) {
    // 先建立数据头部和缓冲区
    Header header;
    PseudoHeader* Phead = new PseudoHeader();
    header.flag = SEQ;
    // 一开始seq和ack都为0
    char* SendBuff = new char[sizeof(header) + DATA_LEN_MAX];
    int WaitBuff[50];

    // 判断状态位
    while (true) {
        // 判断一下要不要关掉线程
        if (CloseFlag)
            break;
        // 判断需不需要重发（重发条件为计时器开启且超时了）

        // 确定哪个超时，需要遍历窗口内的每一个定时器，关键是一次循环只重发那一个
        int tempIndex = WaitBeginIndex;
        while (true) {
            if (CloseFlag)
                return 0;
            mtx.lock();// 不能被recv线程给改了..
            TimerClass* tempTimer = Timers[tempIndex];
            // copy一份这个waitackbuff数组
            for (int i = 0;i < WindowSize;i++)
                WaitBuff[i] = WaitAckBuff[i];
            mtx.unlock();

            if (WaitBuff[tempIndex] != -1) {
                if (tempTimer->flag==1&&clock() - tempTimer->timer > WAITING_MAX) {
                    break;
                }
            }
            tempIndex++;
            tempIndex = tempIndex >= WindowSize ? tempIndex - WindowSize : tempIndex;
        }
       

        // 确定一下要重发的哪个
        int seq = WaitBuff[tempIndex];
        header.seq = seq;
        header.Checksum = Phead->Cal_Checksum(&header);

        cout << "[client]:数据包" << seq << "超时重发ing" << endl;

        // tempByte不能回退了这次
        int Templen = seq == tally ? ByteNum - (tally - 1) * DATA_LEN_MAX : DATA_LEN_MAX;
        // 先把数据报头放入缓冲区，再放入Data
        memcpy(SendBuff, &header, sizeof(header));
        memcpy(SendBuff + sizeof(header), SendData + (seq-1)* DATA_LEN_MAX, Templen);
        while (sendto(ClientSocket, SendBuff, sizeof(header) + Templen, 0, (SOCKADDR*)&ServerAddress, ServerAddLen) < 0)
            ;
        cout << "[client]:成功【重发】数据包" << seq << endl;

        // 记得重新开始计时
        /*for (int i = 0;i < 4;i++)
            cout << WaitAckBuff << ":"<<(Timers[i]==nullptr);
        cout << endl;*/
        mtx.lock();
        Timers[tempIndex]->set();
        mtx.unlock();
    }

    return 0;

}

void ClientCloseConnection() {
    // 发起1和4，接收2和3
    Header header;
    char* RecvBuff = new char[1000];
    char* SendBuff = new char[1000];


    /**** 发起第一次挥手请求 ****/
    // 设置数据头信息
    header.flag = FIN_ACK;
    header.fin = 1;
    // 生成伪首部，计算校验和
    PseudoHeader* Phead = new PseudoHeader();
    header.Checksum = Phead->Cal_Checksum(&header);

    // header存到缓冲区，准备发送
    memcpy(SendBuff, &header, sizeof(header));
    while (sendto(ClientSocket, SendBuff, sizeof(header), 0, (SOCKADDR*)&ServerAddress, ServerAddLen) == false) {
        // cout << "第一次挥手发送数据失败！" << endl;
        ;
    }
    cout << "[client]:第一次挥手消息发送成功！" << endl;
    header.print();


    /**** 接收第二次挥手请求 ****/
    // 记得计时
    header.reset();
    clock_t time = clock();
    while (true) {
        int recv_len = recvfrom(ClientSocket, RecvBuff, sizeof(header), 0, (SOCKADDR*)&ServerAddress, &ServerAddLen);
        // 还是先判断是否超时
        if (clock() - time > WAITING_MAX) {
            // 超时须重发
            // cout << "第一或二次挥手消息传输超时！" << endl;
            // cout << "正在重发第一次挥手消息......" << endl;

            int send_len = sendto(ClientSocket, SendBuff, sizeof(header), 0, (SOCKADDR*)&ServerAddress, ServerAddLen);
            if (send_len < 0) {
                cout << "[client]:第一次挥手发送数据失败！" << endl;
                break;
            }
            // cout << "[client]:第一次挥手消息发送成功！" << endl;
            //header.print();
            // ！！！！重新计时
            time = clock();
            continue; // 然后继续等待接收第二次挥手的消息
        }
        // 没有超时
        if (recv_len < 0) {
            // cout << "[client]:第二次挥手消息接收ing......" << endl;
            continue;
        }
        memcpy(&header, RecvBuff, sizeof(header));
        // 差错检验
        if (header.flag == ACK && header.ack == 1 && CheckError(&header, sizeof(header)) == true) {
            cout << "[client]:第二次挥手消息接收成功！" << endl;
            break;// 跳出循环
        }
        //cout << "第二次挥手数据检验不通过！" << endl;
        //cout << "正在重新接收第二次挥手消息......" << endl;
    }


    /**** 接收第三次挥手请求 ****/
    header.reset();
    while (true) {
        int recv_len = recvfrom(ClientSocket, RecvBuff, sizeof(header), 0, (SOCKADDR*)&ServerAddress, &ServerAddLen);
        if (recv_len < 0) {
            // cout << " 第三次挥手消息接收ing......" << endl;
            continue;
        }
        memcpy(&header, RecvBuff, sizeof(header));
        // 差错检验
        if (header.flag == FIN && header.fin == 1 && CheckError(&header, sizeof(header)) == true) {
            cout << "[client]:第三次挥手消息接收成功！" << endl;
            break;// 跳出循环
        }
        //cout << "第三次挥手数据检验不通过！" << endl;
        //cout << "正在重新接收第三次挥手消息......" << endl;
    }



    /**** 发起第四次挥手请求 ****/
    // 设置数据头信息
    header.reset();
    header.flag = ACK;
    header.ack = 2;// 接收到了2和3
    // 生成伪首部，计算校验和
    header.Checksum = Phead->Cal_Checksum(&header);

    // header存到缓冲区，准备发送
    //cout << "[client]:第四次挥手消息发送ing......" << endl;
    memcpy(SendBuff, &header, sizeof(header));
    while (sendto(ClientSocket, SendBuff, sizeof(header), 0, (SOCKADDR*)&ServerAddress, ServerAddLen) == false) {
        // cout << "第四次挥手发送数据失败！" << endl;
        ;
    }
    cout << "[client]:第四次挥手消息发送成功！" << endl;
    header.print();
    cout << "客户端正常结束并退出" << endl;



}

int main() {
    // 初始化
    init();

    cout << "客户端发起连接建立请求..." << endl;
    // 三次握手建立连接
    if (ClientConnect() == -1) {
        cout << "建立连接失败！" << endl;
    }

    cout << "请输入窗口大小：" << endl;
    cin >> WindowSize;
    // 初始化Wait数组全为-1
    for (int i = 0;i < WindowSize;i++) {
        WaitAckBuff[i] = -1;
        Timers[i] = new TimerClass();
    }

    cout << "请输入丢包率：" << endl;
    cin >> Loss;

    cout << "请输入延时：" << endl;
    cin >> timmer;

    cout << "/****** 输入需要传输的文件名字 ******/" << endl;
    cin >> figName;

    /**** 建立三个线程 ****/
    HANDLE handle_send = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)SendMessageThread, &ClientSocket, 0, 0);
    HANDLE handle_recv = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)RecvMessageThread, &ClientSocket, 0, 0);
    HANDLE handle_Resend = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)SR_ReSendMessageThread, &ClientSocket, 0, 0);

    // 检测发送线程是否结束
    // 等待线程结束
    DWORD send_thred_result = WaitForSingleObject(handle_send, INFINITE);
    while (send_thred_result != WAIT_OBJECT_0)
        continue;

    CloseFlag = 1;// 关掉另外俩线程
    
    // 四次挥手结束连接
    ClientCloseConnection();

    while (true) {
        ;
    }


    return 0;

}