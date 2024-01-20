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
#define WAITING_MAX 1000
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
double Loss = 0.2;


// 存储data的数组（char*类型，和缓冲区一样）
char* SendData;

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
        else if(flag == FIN_ACK)
            cout << "flag:FIN,ACK  fin:" <<fin<< "  ack:" << ack << "  Checksum  " << Checksum << endl;
        else if(flag == SEQ)
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
    while (sendto(ClientSocket, SendBuff, sizeof(header), 0, (SOCKADDR*)&ServerAddress, ServerAddLen)== -1 ) {
        // cout << "第一次握手发送数据失败！" << endl;
        // cout << "1";
        cout << WSAGetLastError()<<endl;
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

void SendMessage() {
    // 先建立数据头部和缓冲区
    Header header;
    PseudoHeader* Phead = new PseudoHeader();
    header.flag = SEQ;
    // 一开始seq和ack都为0
    char* RecvBuff = new char[sizeof(header)];
    char* SendBuff = new char[sizeof(header) + DATA_LEN_MAX];
    // data清空
    SendData = new char[DATA_ALL];


    /**** 加载数据 ****/
    cout << "/****** 输入需要传输的文件名字 ******/" << endl;
    string figName;
    cin >> figName;
    // 打开文件
    ifstream is("file//"+figName, ifstream::binary);
    // 和server端不同的是不知道文件大小，只能一个一个读入
    unsigned long long int ByteNum = 0;
    unsigned char temp = is.get();
    while (is) {
        SendData[ByteNum++] = temp;
        temp = is.get();
    }
    cout << "[client]:文件已经成功读入，大小为" << ByteNum << "字节" << endl;
    is.close();

    /**** 传输数据 ****/
    // 只分0和1
    // 先计算一下要传多少次，然后设置丢包率
    int tally = ByteNum / DATA_LEN_MAX+1;
    cout << "[client]:文件即将拆分成" << tally << "个包进行传输" << endl;
    int TempGroup = 0;// 从分组0开始传送
    unsigned long long int TempByte = 0;// 已经传输过去的字节数量
    clock_t time = clock();// 后面加
    int TempTally = 0;//已经传过去的包数
    int loss_pck = 0;
    int count_pck = tally * Loss;
    clock_t begin = clock();

    while (true) {
        // 每次进循环需要先将报文数据打包至缓冲区
        header.reset();
        header.flag = SEQ;
        header.seq = TempGroup; // 用序列号记录
        header.Checksum = Phead->Cal_Checksum(&header);
        // 最后一次发剩下的
        int Templen = (TempTally == tally - 1) ? ByteNum - TempByte : DATA_LEN_MAX;
        // 先把数据报头放入缓冲区，再放入Data
        memcpy(SendBuff, &header, sizeof(header));
        memcpy(SendBuff + sizeof(header), SendData + TempByte, Templen);
        // 每10个丢个包
        if (TempTally % count_pck == 1) {
            cout << "[client]:分组" << TempGroup << "丢包[" << TempTally << "]测试......" << endl;
            time = clock();
            //延时！
            // Sleep(3000);// 等待回应的时候肯定超时

            //while (sendto(ClientSocket, SendBuff, sizeof(header) + Templen, 0, (SOCKADDR*)&ServerAddress, ServerAddLen) < 0)
            //    ;//cout << WSAGetLastError() << endl;
            //cout << "[client]:成功发送分组" << TempGroup << "的数据包[" << TempTally << "]！" << endl;
            //time = clock();
        }
        else {// 正常发
            while (sendto(ClientSocket, SendBuff, sizeof(header) + Templen, 0, (SOCKADDR*)&ServerAddress, ServerAddLen) < 0)
                ;//cout << WSAGetLastError() << endl;
            cout << "[client]:成功发送分组" << TempGroup << "的数据包[" << TempTally << "]！" << endl;
            header.print();
            time = clock();
        }
        // 然后等待回应
        // 发完就开始计时
        while (true) {
            header.reset();
            if (clock() - time > WAITING_MAX) {
                cout<<"[client]:分组" << TempGroup << "的数据包[" << TempTally  << "]超时，正在重新发送......" << endl;
                loss_pck++;// 丢包数++
                while (sendto(ClientSocket, SendBuff, sizeof(header) + Templen, 0, (SOCKADDR*)&ServerAddress, ServerAddLen) < 0)
                    ;//cout << WSAGetLastError() << endl;
                cout << "[client]:成功发送分组" << TempGroup << "的数据包[" << TempTally << "]！" << endl;
                header.print();
                // 记得重新计时！！！
                time = clock();
            }
            // cout << "!" << endl;
            int recv_len = recvfrom(ClientSocket, RecvBuff, sizeof(header), 0, (SOCKADDR*)&ServerAddress, &ServerAddLen);
            // cout << WSAGetLastError();
            // cout << TempTally << endl;
            if (recv_len < 0)
                continue;
            // 接收到了进行确认
            memcpy(&header, RecvBuff, sizeof(header));
            if (header.ack == TempGroup && CheckError(&header, sizeof(header)) == true) {
                // 确认了再给TempTally++
                cout << "[client]:已确认分组" << TempGroup << "的数据包[" << TempTally++ << "]发送成功！" << endl;
                TempByte += Templen;
                cout << "tempBtye" << TempByte << endl;
                break;
            }   
        }
        // 然后进行下一个
        if (TempTally >= tally) {
            cout << "[client]:全部数据包发送完毕......" << endl;
            break;
        }
        // 修改信息
        TempGroup = (TempGroup + 1) % 2;
        // 延时等待一会儿再发下一个
    }


    // 发送结束的报文OVER=1
    header.reset();
    header.seq = (TempGroup + 1) % 2;// 还是需要下一个分组来发
    header.flag = OVER;
    header.Checksum = Phead->Cal_Checksum(&header);
    memcpy(SendBuff, &header, sizeof(header));
    while (sendto(ClientSocket, SendBuff, sizeof(header), 0, (SOCKADDR*)&ServerAddress, ServerAddLen) < 0)
        ;

    // 发送端计算延时和吞吐率
    clock_t time_total = clock() - begin;
    double seed = (double)ByteNum / time_total;
    double loss = (double)loss_pck / tally;
    cout << "/************************************************************/" << endl;
    cout << "[client]:本次传输共发送" << ByteNum << "个字节，" << tally << "个数据包" << endl;
    cout << "    耗时:" << time_total << "ms" << endl;
    cout << "    吞吐率:" << seed << " Byte / ms"<<endl;

    cout << "[client]:传输关闭......" << endl;




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
            cout << "[client]:第一次挥手消息发送成功！" << endl;
            header.print();
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

    cout << "请输入丢包率：" << endl;
    cin >> Loss;

    // 数据传输
    SendMessage();

    // 四次挥手结束连接
    ClientCloseConnection();

    while (true) {
        ;
    }
    

    return 0;

}