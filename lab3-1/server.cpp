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

using namespace std;
#pragma comment(lib,"ws2_32.lib")
#define WAITING_MAX 10000
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
const uint16_t SOURCE_PORT = 8887;
const uint16_t DESTINATION_PORT = 8888;

string savePath;

/**** 全局变量定义****/
// 套接字
SOCKET ServerSocket;
// 地址
SOCKADDR_IN ServerAddress;
SOCKADDR_IN ClientAddress;
int ServerAddLen;
int ClientAddLen;
WSADATA wsaData;

// 存储data的数组（char*类型，和缓冲区一样）
char* RecvData;
int timmer=20;

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
        int size = sizeof(*head) + sizeof(SourceIp)+sizeof(DestIp);// 32位+32位
        // int size = sizeof(*head);
        // cout << size << endl;
        int count = size / 2; // 16位==2字节
        u_short* buf = (u_short*)malloc(size);
        // 先全部清0
        memset(buf, 0, size);
        memcpy(buf, head, sizeof(*head));
        memcpy(buf + sizeof(*head), &SourceIp, sizeof(SourceIp));
        memcpy(buf + sizeof(*head) + sizeof(SourceIp), &DestIp, sizeof(DestIp));
        u_long res = 0;
        for (int i = 0;i < count;i++) {
            //  << res << " ";
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

// 服务器端初始化
void init() {
    // 初始化套接字
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    // 设置服务器端地址
    ServerAddress.sin_family = AF_INET;
    ServerAddress.sin_addr.s_addr = htonl(2130706433);
    ServerAddress.sin_port = htons(8887);

    // 设置客户端地址
    ClientAddress.sin_family = AF_INET;
    ClientAddress.sin_addr.s_addr = htonl(2130706433);
    ClientAddress.sin_port = htons(8888);

    // // 设置路由器的地址
    // RouterAddress.sin_family = AF_INET;
    // RouterAddress.sin_addr.s_addr = htonl(0x7f01);
    // RouterAddress.sin_port = htond(8888);

    // 绑定服务端
    ServerSocket = socket(AF_INET, SOCK_DGRAM, 0);
    int bind_res = bind(ServerSocket, (sockaddr*)&ServerAddress, sizeof(ServerAddress));
    if (bind_res == SOCKET_ERROR) {
        cout << "server: bind failed." << endl;
    }

    unsigned long on = 1;
    ioctlsocket(ServerSocket, FIONBIO, &on);

    ClientAddLen = sizeof(ClientAddress);
    ServerAddLen = sizeof(ServerAddress);

    cout << "服务器端初始化完成！" << endl;
}

// 辅助函数：差错检验
bool CheckError(Header* head, int len) {
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

// 三次握手建立连接
int ServerConnect() {
    // 1，3服务器接收，2服务器发送
    Header header;
    // 两个缓冲区
    char* RecvBuff = new char[1000];
    char* SendBuff = new char[1000];
    cout << "服务器开始等待连接......" << endl;

    /**** 第一次握手 ****/
    cout << "[server]:等待第一次握手..." << endl;
    while (true) {
        // 通过recvfrom函数接收报文，第一次握手发来的只有数据头
        int recv_len = recvfrom(ServerSocket, RecvBuff, sizeof(header), 0, (sockaddr*)&ClientAddress, &ClientAddLen);
        if (recv_len < 0) {
            // cout << "第一次握手接收ing......" << endl;
            continue;
        }
        // 接收到消息后，给header赋值并读取
        memcpy(&header, RecvBuff, sizeof(header));
        // cout << header.flag << endl;

        // 对header进行差错检验
        if (header.flag == SYN && CheckError(&header, sizeof(header)) == true) {
            cout << "[server]:第一次握手消息接收成功！" << endl;
            break;// 跳出循环
        }
        //cout << "第一次握手数据检验不通过！" << endl;
        //cout << "正在重新接收第一次握手消息......" << endl;
    }


    /**** 发起第二次握手 ****/
    // 创建header（修改信息）
    header.reset();
    header.flag = SYN_ACK;
    header.ack = 1;
    // 生成伪首部，计算校验和
    PseudoHeader* Phead = new PseudoHeader();
    header.Checksum = Phead->Cal_Checksum(&header);

    // header存到缓冲区，准备发送
    memcpy(SendBuff, &header, sizeof(header));
    while (sendto(ServerSocket, SendBuff, sizeof(header), 0, (SOCKADDR*)&ClientAddress, ClientAddLen) == false) {
        // cout << "第二次握手发送数据失败！" << endl;
        ;
    }
    cout << "[server]:第二次握手消息发送成功！" << endl;
    header.print();

    /**** 接收第三次握手 ****/
    // 通过while循环等待接收客户端发来的消息，超时则需要重传第二次握手
    // 开始计时
    header.reset();
    clock_t time = clock();
    while (true) {
        int recv_len = recvfrom(ServerSocket, RecvBuff, sizeof(header), 0, (sockaddr*)&ClientAddress, &ClientAddLen);
        // 一直没有收到
        if (clock() - time > WAITING_MAX) {
            // cout << "第二或三次握手消息传输超时！" << endl;
            // cout << "正在重发第二次握手消息......" << endl;
            int send_len = sendto(ServerSocket, SendBuff, sizeof(header), 0, (SOCKADDR*)&ClientAddress, ClientAddLen);
            if (send_len < 0) {
                cout << "[server]:第二次握手发送数据失败！" << endl;
                return -1;
            }
            cout << "[server]:第二次握手消息发送成功！" << endl;
            header.print();
            // ！！！！重新计时
            time = clock();
            continue; // 然后继续等待接收第三次握手的消息
        }
        // 没有超时的话
        if (recv_len < 0) {
            // cout << "第三次握手消息接收ing......" << endl;
            // cout<< WSAGetLastError() << endl;
            continue;
        }
        // 接收到消息后，给header赋值并读取
        memcpy(&header, RecvBuff, sizeof(header));
        // 对header进行差错检验
        if (header.flag == ACK && header.ack == 1 && CheckError(&header, sizeof(header)) == true) {
            cout << "[server]:第三次握手消息接收成功！" << endl;
            break;// 跳出循环
        }
        //cout << "第三次握手数据检验不通过！" << endl;
        //cout << "正在重新接收第三次握手消息......" << endl;
    }

    // 握手成功后
    //cout << "第三次握手成功！" << endl;
    cout << "[server]:等待接收数据ing......" << endl;
    return 1;

}

void RecvMessage() {
    // 先建立数据头部和缓冲区
    Header header;
    header.flag = ACK;
    // 一开始seq和ack都为0
    char* RecvBuff = new char[sizeof(header) + DATA_LEN_MAX];
    char* SendBuff = new char[sizeof(header)];
    // data清空
    RecvData = new char[DATA_ALL];

    // 通过while循环实现对分组0和1的递归接收
    int TempGroup = 0;
    unsigned long long int ByteNum = 0;
    int pckNum = 0;
    while (true) {
        // Sleep(300);
        // 一进循环首先接收
        header.reset();
        int recv_len = recvfrom(ServerSocket, RecvBuff, sizeof(header) + DATA_LEN_MAX, 0, (sockaddr*)&ClientAddress, &ClientAddLen);
        if (recv_len < 0)
            continue;
        // 报文长度不为0时，头部赋值给head，并进行差错检测
        memcpy(&header, RecvBuff, sizeof(header));
        if (CheckError(&header, sizeof(header)) == false || header.seq != TempGroup) {
            // cout << "[server]:分组" << TempGroup << "的数据报接收失败！" << endl;8
            // 需要发送上一次的报文
            TempGroup = (TempGroup + 1) % 2; // 0/1置换
            // SendBuff没有变
            while (sendto(ServerSocket, SendBuff, sizeof(header), 0, (SOCKADDR*)&ClientAddress, ClientAddLen) < 0) {
                ;
            }
            // continue; // 等待重传，不传Ack0将会超时，下一个循环还是报文0
        }
        cout << "[server]:分组" << TempGroup << "发来的数据报["<< pckNum++ <<"]接收成功！" << endl;

        // 接收成功，保存data，并发送Ack
        // 先检查一下是不是over（发完了）
        if (header.flag == OVER) {
            cout << "[server]:开始解析发来的全部数据包......" << endl;
            RecvData[ByteNum] = '\0';
            string path =  "D:\\test_code\\computer-network\\server\\"+savePath;
            // 输出流
            ofstream os(path.c_str(), ofstream::binary);
            for (int i = 0;i < ByteNum;i++)
                os << RecvData[i];
            os.close();
            return;
        }
        else {
            // 正常保存数据到data就行，从ByteNum开始存
            memcpy(RecvData + ByteNum, RecvBuff + sizeof(header), recv_len - sizeof(header));
            ByteNum += recv_len - sizeof(header); // 保留减去报头的数据
        }

        // 接收端延时（一般都是速度：传>收）
        Sleep(timmer);
        header.reset();
        header.ack = TempGroup; // 确认收到分组
        header.flag = ACK;
        // 计算校验位
        PseudoHeader* Phead = new PseudoHeader();
        header.Checksum = Phead->Cal_Checksum(&header);
        memcpy(SendBuff, &header, sizeof(header));
        while (sendto(ServerSocket, SendBuff, sizeof(header), 0, (SOCKADDR*)&ClientAddress, ClientAddLen) < 0) {
            // cout << "分组" << TempGroup << "的Ack发送失败！" << endl;
        }
        header.print();
        // 等待下一次
        TempGroup = (TempGroup + 1) % 2; // 0/1置换
        cout << "[server]:等待分组" << TempGroup << "发来的数据......" << endl;
    }

}

// 四次挥手的接收方，关闭连接
void ServerCloseConnection() {
    Header header;
    char* RecvBuff = new char[1000];
    char* SendBuff = new char[1000];

    /**** 等待第一次挥手请求 ****/
    while (true) {
        int recv_len = recvfrom(ServerSocket, RecvBuff, sizeof(header), 0, (SOCKADDR*)&ClientAddress, &ClientAddLen);
        if (recv_len < 0) {
            //cout << "第一次挥手请求等待ing" << endl;
            continue;
        }
        // 接收到消息后，给header赋值并读取
        memcpy(&header, RecvBuff, sizeof(header));
        // 对header进行差错检验
        if (header.flag == FIN_ACK && header.fin == 1 && CheckError(&header, sizeof(header)) == true) {
            cout << "[server]:第一次挥手消息接收成功！" << endl;
            break;// 跳出循环
        }
        //cout << "第一次挥手数据检验不通过！" << endl;
        //cout << "正在重新接收第一次挥手消息......" << endl;
    }

    /**** 发起第二次挥手 ****/
    // 先修改header的信息
    header.reset();
    header.flag = ACK;
    header.ack = 1;
    // 创建伪首部并校验
    PseudoHeader* Phead = new PseudoHeader();
    header.Checksum = Phead->Cal_Checksum(&header);
    // 装进发送缓冲区
    memcpy(SendBuff, &header, sizeof(header));
    // 开始发送并计时
    while (sendto(ServerSocket, SendBuff, sizeof(header), 0, (SOCKADDR*)&ClientAddress, ClientAddLen) < 0) {
        // cout << "第二次挥手消息发送ing......" << endl;
        ;
    }
    cout << "[server]:第二次挥手消息发送成功！" << endl;
    header.print();

    /**** 发送第三次挥手消息 ****/
    // 先修改头
    header.reset();
    header.flag = FIN;
    header.ack = 1;// 只收到一条
    header.fin = 1;// 也要关闭了
    // 伪首部校验
    header.Checksum = Phead->Cal_Checksum(&header);
    // 装进发送缓冲区
    memcpy(SendBuff, &header, sizeof(header));
    // 开始发送并计时
    while (sendto(ServerSocket, SendBuff, sizeof(header), 0, (SOCKADDR*)&ClientAddress, ClientAddLen) < 0) {
        // cout << "第三次挥手消息发送ing......" << endl;
        ;
    }
    cout << "[server]:第三次挥手消息发送成功！" << endl;
    header.print();

    /**** 接收第四次挥手 ****/
    header.reset();
    clock_t time = clock();
    while (true) {
        int recv_len = recvfrom(ServerSocket, RecvBuff, sizeof(header), 0, (SOCKADDR*)&ClientAddress, &ClientAddLen);
        if (recv_len < 0) {
            // cout << "第四次挥手消息接收ing......" << endl;
            continue;
        }
        // 到这里成功接收了
        memcpy(&header, RecvBuff, sizeof(header));
        // 差错检验
        if (header.flag == ACK && header.ack == 2 && CheckError(&header, sizeof(header)) == true) {
            cout << "[server]:第四次挥手消息接收成功！" << endl;
            break;// 跳出循环
        }
        //cout << "第四次挥手数据检验不通过！" << endl;
        //cout << "正在重新接收第四次挥手消息......" << endl;
    }

    // 握手结束
    cout << "服务器端正常结束并退出" << endl;
    Sleep(timmer);


}



// 服务器端的主函数
int main() {
    // 初始化
    init();


    // 三次握手建立连接
    int connect_res = ServerConnect();
    if (connect_res == -1) {
        cout << "【Warning:】连接建立失败，服务器即将关闭！" << endl;
        Sleep(50);
        return -1;
    }

    cout << "输入延时" << endl;
    cin >> timmer;

    cout << "输入保存文件名字" << endl;
    cin >> savePath;

    // 数据传输
    RecvMessage();

    // 四次挥手结束连接
    ServerCloseConnection();

    while (true) {
        ;
    }

    return 0;

}








