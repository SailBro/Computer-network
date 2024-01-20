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

/**** һЩ��������****/
// IP��32λ���Ͷ˿ڣ�16λ��
const uint32_t SOURCE_IP = 2130706433;
const uint32_t DESTINATION_IP = 2130706433;
const uint16_t SOURCE_PORT = 8888;
const uint16_t DESTINATION_PORT = 8887;

/**** ȫ�ֱ�������****/
// �׽���
SOCKET ClientSocket;
// ��ַ
SOCKADDR_IN ServerAddress;
SOCKADDR_IN ClientAddress;
int ServerAddLen;
int ClientAddLen;
WSADATA wsaData;
double Loss = 0.2;
string figName;
/**** ������GBN�������� ****/ 
// �����߳�
int WindowSize = 4;
int BasePointer = 1;
int NextSeqPointer = 1;
// �����߳�
// int RecvAck = -1;
// bool RecvFlag = 0;
// �ط��߳�
// bool ReSendFlag = 0;
// int StartSeq = -1;
// int EndSeq = -1;

// ��ʱ
int timmer=0;

// ��ʱ��
clock_t Timer;
// ��ʱ������
bool TimeFlag = 1;
mutex mtx;  // ������


unsigned long long int TempByte = 0;// �Ѿ������ȥ���ֽ�����
int tally; // ���͵����ݰ��ĸ���
unsigned long long int ByteNum = 0;
int CloseFlag = 0;



// �洢data�����飨char*���ͣ��ͻ�����һ����
char* SendData;

class PseudoHeader;// α�ײ�

// ����ͷ��ʽ
class Header {
public:
    uint16_t SourcePort; // Դ�˿ں�
    uint16_t DestPort; // Ŀ�Ķ˿ں�
    uint16_t len; // ����
    uint16_t Checksum; // У���
    int ack; // ȷ�Ϻ�
    int seq; // ���к�
    int flag; // ��־λ
    int fin; // ������־

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

    // ���ö˿�
    void resetPort() {
        SourcePort = SOURCE_PORT;
        DestPort = DESTINATION_PORT;
    }

    // �˿�ȡ��
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

// α�ײ�������UDPУ��
class PseudoHeader {
public:
    uint32_t SourceIp; // ԴIP��ַ
    uint32_t DestIp; // Ŀ��IP��ַ
    uint8_t Protovol; // Э��
    uint16_t len;// ����
    PseudoHeader() {
        SourceIp = SOURCE_IP;
        DestIp = DESTINATION_IP;
        Protovol = len = 0;
    }

    // IPȡ��
    void reserveIP() {
        SourceIp = DESTINATION_IP;
        DestIp = SOURCE_IP;
    }

    // �������������ͷ��У���
    uint16_t Cal_Checksum(Header* head) {
        // return 0;
        head->resetPort();
        int size = sizeof(*head) + sizeof(SourceIp)+sizeof(DestIp);// 32λ+32λ
        // int size = sizeof(*head);
        // cout << size << endl;
        int count = size / 2; // 16λ==2�ֽ�
        u_short* buf = (u_short*)malloc(size);
        // ��ȫ����0
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
            // ���ʱ��Ҫ+1
            if (res & 0xffff0000) {
                // ��16λ��Ϊ0
                res &= 0xffff;
                res++;
            }
        }
        return ~(res & 0xffff);// ������16λ
    }
};

void init() {
    // ��ʼ���׽���
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    
    //ioctlsocket(ClientSocket, FIONBIO, &unblockmode);

    // ���÷������˵�ַ
    ServerAddress.sin_family = AF_INET;
    ServerAddress.sin_addr.s_addr = htonl(2130706433);
    ServerAddress.sin_port = htons(8887);

    // ���ÿͻ��˵�ַ
    ClientAddress.sin_family = AF_INET;
    ClientAddress.sin_addr.s_addr = htonl(2130706433);
    ClientAddress.sin_port = htons(8888);

    // �󶨿ͻ���
    ClientSocket = socket(AF_INET, SOCK_DGRAM, 0);
    int bind_res = bind(ClientSocket, (sockaddr*)&ClientAddress, sizeof(ClientAddress));
    if (bind_res == SOCKET_ERROR) {
        cout << "client: bind failed." << endl;
    }

    unsigned long on = 1;
    ioctlsocket(ClientSocket, FIONBIO, &on);

    ClientAddLen = sizeof(ClientAddress);
    ServerAddLen = sizeof(ServerAddress);
  
    cout << "�ͻ��˶˳�ʼ����ɣ�" << endl;

}

// ����������������
bool CheckError(Header* head, int len) {
    // return true;
    // ����������α�ײ�������У��λ
    PseudoHeader* Phead = new PseudoHeader();
    // IPȡ��
    Phead->reserveIP();
    // ��head�Ķ˿�ȡ��
    head->reservePort();
    if (head->Checksum == Phead->Cal_Checksum(head))
        return true;// ͨ������
    // cout << "ERROR:" << head->Checksum << "," << Phead->Cal_Checksum(head) << endl;
    // head->print();
    return true;
}

int ClientConnect() {
    // ��Ҫ��ɷ���1��3����


    /**** �����һ���������� ****/
    // �½�����ͷ������������
    Header header;
    header.flag = SEQ;
    char* RecvBuff = new char[1000];
    char* SendBuff = new char[1000];
    // cout << sizeof(SendBuff) << endl;
    // cout << "�ͻ��˿�ʼ�ȴ�����......" << endl;

    // ��������ͷ��Ϣ
    header.flag = SYN;
    // ����α�ײ�������У���
    PseudoHeader* Phead = new PseudoHeader();
    header.Checksum = Phead->Cal_Checksum(&header);

    // header�浽��������׼������
    // cout << "[client]:��һ��������Ϣ����ing......" << endl;
    memcpy(SendBuff, &header, sizeof(header));
    // cout << sizeof(header)<<" "<<sizeof(SendBuff) << endl;
    // header.print();
    while (sendto(ClientSocket, SendBuff, sizeof(header), 0, (SOCKADDR*)&ServerAddress, ServerAddLen)== -1 ) {
        // cout << "��һ�����ַ�������ʧ�ܣ�" << endl;
        // cout << "1";
        cout << WSAGetLastError()<<endl;
    }
    cout << "[client]:��һ�����ַ������ݳɹ���" << endl;
    header.print();


    /**** ���յڶ���������Ϣ ****/

    // �ǵÿ�ʼ��ʱ
    header.reset();
    clock_t time = clock();
    while (true) {
        int recv_len = recvfrom(ClientSocket, RecvBuff, sizeof(header), 0, (SOCKADDR*)&ServerAddress, &ServerAddLen);
        // �������ж��Ƿ�ʱ
        if (clock() - time > WAITING_MAX) {
            // ��ʱ���ط�
            // cout << "��һ�����������Ϣ���䳬ʱ��" << endl;
            // cout << "�����ط���һ��������Ϣ......" << endl;
            int send_len = sendto(ClientSocket, SendBuff, sizeof(header), 0, (SOCKADDR*)&ServerAddress, ServerAddLen);
            if (send_len < 0) {
                cout << "��һ�����ַ�������ʧ�ܣ�" << endl;
                return -1;
            }
            cout << "[client]:��һ��������Ϣ���ͳɹ���" << endl;
            header.print();
            // �����������¼�ʱ
            time = clock();
            continue; // Ȼ������ȴ����յڶ������ֵ���Ϣ
        }
        // û�г�ʱ
        if (recv_len < 0) {
            // cout << " �ڶ���������Ϣ����ing......" << endl;
            continue;
        }
        memcpy(&header, RecvBuff, sizeof(header));
        // ������
        if (header.flag == SYN_ACK && header.ack == 1 && CheckError(&header, sizeof(header)) == true) {
            cout << "[client]:�ڶ���������Ϣ���ճɹ���" << endl;
            break;// ����ѭ��
        }
        // cout << "�ڶ����������ݼ��鲻ͨ����" << endl;
        // cout << "�������½��յڶ���������Ϣ......" << endl;
    }


    /**** ������������� ****/
    // ��������ͷ��Ϣ
    header.reset();
    header.flag = ACK;
    header.ack = 1;// ���յ��˵ڶ�������
    // ����α�ײ�������У���
    header.Checksum = Phead->Cal_Checksum(&header);

    // header�浽��������׼������
    cout << "[client]:������������Ϣ���ͳɹ���" << endl;
    header.print();
    memcpy(SendBuff, &header, sizeof(header));
    while (sendto(ClientSocket, SendBuff, sizeof(header), 0, (SOCKADDR*)&ServerAddress, ServerAddLen) == false) {
        // cout << "���������ַ�������ʧ�ܣ�" << endl;
    }

    // cout << "[client]:���������ֳɹ���" << endl;
    cout << "[client]:��ʼ��������......" << endl;


    return 0;
}

DWORD WINAPI SendMessageThread(void* param) {

    // �Ƚ�������ͷ���ͻ�����
    Header header;
    PseudoHeader* Phead = new PseudoHeader();
    header.flag = SEQ;
    // һ��ʼseq��ack��Ϊ0
    char* SendBuff = new char[sizeof(header) + DATA_LEN_MAX];
    // data���
    SendData = new char[DATA_ALL];


    /**** �������� ****/
    // ���ļ�
    ifstream is("file//"+figName, ifstream::binary);

    // ��server�˲�ͬ���ǲ�֪���ļ���С��ֻ��һ��һ������
    unsigned char temp = is.get();
    while (is) {
        SendData[ByteNum++] = temp;
        temp = is.get();
    }
    cout << "[client]:�ļ��Ѿ��ɹ����룬��СΪ" << ByteNum << "�ֽ�" << endl;
    is.close();


    /**** ��������ǰ��׼�� ****/
    // �����0~2^k-1(kΪWindowSize)
    // �ȼ���һ��Ҫ�����ٴΣ�Ȼ�����ö�����
    tally = ByteNum / DATA_LEN_MAX+1;
    cout << "[client]:�ļ�������ֳ�" << tally << "�������д���" << endl;
    int loss_pck = 1/Loss;
    int loss = 0;
    clock_t begin = clock();
    // ������߳��У����͵ı��ı�־λ�̶�ΪSEQ
    header.flag = SEQ;

    /**** �������ݣ�ͨ��ѭ��ʵ��һֱ�� ****/
    // ��һ�η�ʱ�������ڲ�����ˮ��ȷ��ack
    /*for (int i = 0;i < WindowSize;i++) {
        header.seq = i;
        header.Checksum = Phead->Cal_Checksum(&header);
        int Templen = (i == tally - 1) ? ByteNum - TempByte : DATA_LEN_MAX;
        // �Ȱ����ݱ�ͷ���뻺�������ٷ���Data
        memcpy(SendBuff, &header, sizeof(header));
        memcpy(SendBuff + sizeof(header), SendData + TempByte, Templen);
        while (sendto(ClientSocket, SendBuff, sizeof(header) + Templen, 0, (SOCKADDR*)&ServerAddress, ServerAddLen) < 0)
            ;
        TempByte += Templen;
        cout << "[client]:�ɹ����ͷ���" << i<< "�����ݰ�[" << i << "]��" << endl;
        Sleep(timmer);
    }
    NextSeqPointer = WindowSize;
    // return 0;

    int failed = 0;
    // ����������
    clock_t time = clock();// �����
    */


    while (true) {

        // ���ж�һ�½��յ���ack��ɶ������������ackȷ�Ϻ�

        // �������һ�½��յ����
        // cout << RecvAck << endl;
        //RecvFlag = 1; // ����/����һ�£�Recv�߳��и���һ������RecvFlag=0��
        // �ȵ�RecvFlag���0�ˣ�˵��Recv�̸߳�����Ack��ֵ�����Ҳ����ٸ�����
        /*while (RecvFlag) {
            if (clock() - time > WAITING_MAX) {
                // ��ʱ��Ҫ���ش��̸߳ɻ�
                ReSendFlag = 1;
                StartSeq = BasePointer;
                EndSeq = -- NextSeqPointer;
                time = clock(); // ���¼�ʱ
                cout << "�ط�ing" << " " << RecvAck << " ��" << BasePointer << "," << NextSeqPointer << "��" << endl;
            }
            continue;
        }
        cout << RecvAck << endl;


        if (ReSendFlag == 1) {
            // �ط��Ļ�û��������һ���ͱ���
            continue;
        }*/

        // �Ե�ǰȷ�ϵ�Ack�����жϣ�ͬʱ�����ظ���Ack
        /*if (RecvAck < BasePointer) {
            if (clock() - time > WAITING_MAX) {
                // ��ʱ��Ҫ���ش��̸߳ɻ�
                ReSendFlag = 1;
                StartSeq = BasePointer;
                EndSeq = NextSeqPointer - 1;
                time = clock(); // ���¼�ʱ
                cout << "�ط�ing" << " " << RecvAck << " ��" <<BasePointer<<","<<NextSeqPointer<<"��"<<endl;
            }
            continue; // �ȴ���һ��Ack
            cout << "�ȴ�ing" << endl;
        }*/

        // ����Ѿ���tally�˾Ͳ����ˣ�������ȷ�϶��յ����߳����˳�������
        /*if (NextSeqPointer == tally) {
            if (RecvAck == NextSeqPointer - 1)
                break;
            else
                continue;
        }*/

        // ���Ack>BasePointer��������󾯸棨����������ᷢ����
        /*if (RecvAck > BasePointer) {
            cout << "[client]:WARNING!" << endl;
            cout << "ack:" << RecvAck << " BasePointer:" << BasePointer << endl;
            failed++;
            if (failed == 10)
                return 0;
            continue;
        }*/

        // �жϴ�����û��
        // if(NextSeqPointer - BasePointer )

        // ����Ļ����������ͣ�ͬʱҲ˵��ǰ��Ľ���OK��
        // cout << RecvAck << endl;

        mtx.lock();
        int tempBase = BasePointer;
        int tempNext = NextSeqPointer;
        mtx.unlock();

        if (tempNext >= tempBase + WindowSize)
            continue;// �ܾ�
        if (tempNext == tally + 1) {
            if (tempBase == tally+1)
                break;
            else
                continue;
        }  
        
        // ��������
        // ÿ�ν�ѭ����Ҫ�Ƚ��������ݴ����������
        header.seq = NextSeqPointer; // �����¸�Seq
        header.Checksum = Phead->Cal_Checksum(&header);
        // ���һ�η�ʣ�µ�
        int Templen = (NextSeqPointer == tally) ? ByteNum - TempByte : DATA_LEN_MAX;
        // �Ȱ����ݱ�ͷ���뻺�������ٷ���Data
        memcpy(SendBuff, &header, sizeof(header));
        memcpy(SendBuff + sizeof(header), SendData + TempByte, Templen);

        // ����Ų��
        // BasePointer += 1;
        // ÿcount_pck��������
        if (NextSeqPointer % loss_pck == 2) {
            loss++;
            cout << "[client]:����" << NextSeqPointer << "����[" << NextSeqPointer << "]����......" <<" base-next��"<<BasePointer << "-" << NextSeqPointer << endl;
            //time = clock();
        }
        else {// ������
            while (sendto(ClientSocket, SendBuff, sizeof(header) + Templen, 0, (SOCKADDR*)&ServerAddress, ServerAddLen) < 0)
                ;//cout << WSAGetLastError() << endl;
            cout << "[client]:�ɹ����ͷ���" << NextSeqPointer << "�����ݰ�[" << NextSeqPointer << "]��"  << " base-next��" << BasePointer << "-" << NextSeqPointer << endl;
            header.print();
            //time = clock();
        }

        
        TempByte += Templen;
        cout << TempByte << endl;

        mtx.lock();
        if (BasePointer == NextSeqPointer) {
            // ��ʼ��ʱ������
            TimeFlag = 1;
            Timer = clock();
        }
        NextSeqPointer++; // ���ͳɹ���+1
        mtx.unlock();

        // ������Ϣ����һ���߳����洦��
        Sleep(timmer);

    }

    // ����over֮ǰ������Ҫ�ж�һ����û��ȫ�����յ�


    // ���ͽ����ı���OVER=1
    header.reset();
    header.seq = NextSeqPointer;// ������Ҫ��һ����������
    header.flag = OVER;
    header.Checksum = Phead->Cal_Checksum(&header);
    memcpy(SendBuff, &header, sizeof(header));
    while (sendto(ClientSocket, SendBuff, sizeof(header), 0, (SOCKADDR*)&ServerAddress, ServerAddLen) < 0)
        ;

    // ���Ͷ˼�����ʱ��������
    clock_t time_total = clock() - begin;
    double seed = (double)ByteNum / time_total;

    cout << "/************************************************************/" << endl;
    cout << "[client]:���δ��乲����" << ByteNum << "���ֽڣ�" << tally << "�����ݰ�" << endl;
    cout << "    ��ʱ:" << time_total << "ms" << endl;
    cout << "    ������:" << seed << " Byte / ms"<<endl;
    cout << "    ������:" << (double)loss / tally <<endl;


    cout << "[client]:����ر�......" << endl;
    cout << "/************************************************************/" << endl;

    return 0;
}

DWORD WINAPI RecvMessageThread(void* param) { 

    // ����ͷ���ͻ�����
    Header header;
    PseudoHeader* Phead = new PseudoHeader();
    header.flag = ACK;
    char* RecvBuff = new char[sizeof(header)];

    // ������߳���һֱ���ղ�����RecvAck����
    while (true) {
        if (CloseFlag)
            break;
        int recv_len = recvfrom(ClientSocket, RecvBuff, sizeof(header), 0, (SOCKADDR*)&ServerAddress, &ServerAddLen);
        if (recv_len < 0 || CheckError(&header, sizeof(header))==false)
            continue;
        // ���յ��˾͸���BasePointer
        mtx.lock();
        memcpy(&header, RecvBuff, sizeof(header));
        // �ۼ�ȷ��
        if (header.ack < BasePointer-1)// ������С��
            continue;
        BasePointer = header.ack+1;
        // cout << "[�����߳�]:���յ�ack" << RecvAck << endl;
        // Ȼ��ȴ���һ�ν���
        
        if (BasePointer == NextSeqPointer)
            TimeFlag = 0;// �ص���ʱ��
        else{
            TimeFlag = 1;// ������ʱ��������
            Timer = clock();
        }
        mtx.unlock();
    }

    return 0;
}

DWORD WINAPI GBN_ReSendMessageThread(void* param) {
    // return 0;
    // �Ƚ�������ͷ���ͻ�����
    Header header;
    PseudoHeader* Phead = new PseudoHeader();
    header.flag = SEQ;
    // һ��ʼseq��ack��Ϊ0
    char* SendBuff = new char[sizeof(header) + DATA_LEN_MAX];

    // �ж�״̬λ
    while (true) {
        // �ж�һ��Ҫ��Ҫ�ص��߳�
        if (CloseFlag)
            break;
        // �ж��費��Ҫ�ط����ط�����Ϊ��ʱ�������ҳ�ʱ�ˣ�
        if (TimeFlag == false||clock()-Timer<=WAITING_MAX)
            continue;
        // ״̬λΪ1ʱһ���Է���
        // ��Ҫ��TempByte��ֵ����һ�£�������������
        mtx.lock();
        int startSeq = BasePointer;
        int endSeq = NextSeqPointer - 1;
        int tpByte = TempByte;
        mtx.unlock();
        for(int i= startSeq;i <= endSeq;i++)
            tpByte -= (i == tally) ? ByteNum% DATA_LEN_MAX : DATA_LEN_MAX;
        for (int i = startSeq;i <= endSeq;i++) {
            header.seq = i;
            header.Checksum = Phead->Cal_Checksum(&header);
            int Templen = (i == tally) ? ByteNum - tpByte : DATA_LEN_MAX;
            // �Ȱ����ݱ�ͷ���뻺�������ٷ���Data
            memcpy(SendBuff, &header, sizeof(header));
            memcpy(SendBuff + sizeof(header), SendData + tpByte, Templen);
            while (sendto(ClientSocket, SendBuff, sizeof(header) + Templen, 0, (SOCKADDR*)&ServerAddress, ServerAddLen) < 0)
                ;
            tpByte += Templen;
            cout << "[client]:�ɹ����ط������ͷ���" << i << "�����ݰ�[" << i << "]�� �ط���Χ��" << startSeq<<"-"<<endSeq<<" base-next��" << BasePointer << "-" << NextSeqPointer <<endl;
            cout << tpByte << endl; 
        }

        // ����ǵ���Ϊ0
        // ReSendFlag = 0;
        // BasePointer++;
        // NextSeqPointer++;
    }

    return 0;

}

void ClientCloseConnection() {
    // ����1��4������2��3
    Header header;
    char* RecvBuff = new char[1000];
    char* SendBuff = new char[1000];


    /**** �����һ�λ������� ****/
    // ��������ͷ��Ϣ
    header.flag = FIN_ACK;
    header.fin = 1;
    // ����α�ײ�������У���
    PseudoHeader* Phead = new PseudoHeader();
    header.Checksum = Phead->Cal_Checksum(&header);

    // header�浽��������׼������
    memcpy(SendBuff, &header, sizeof(header));
    while (sendto(ClientSocket, SendBuff, sizeof(header), 0, (SOCKADDR*)&ServerAddress, ServerAddLen) == false) {
        // cout << "��һ�λ��ַ�������ʧ�ܣ�" << endl;
        ;
    }
    cout << "[client]:��һ�λ�����Ϣ���ͳɹ���" << endl;
    header.print();


    /**** ���յڶ��λ������� ****/
    // �ǵü�ʱ
    header.reset();
    clock_t time = clock();
    while (true) {
        int recv_len = recvfrom(ClientSocket, RecvBuff, sizeof(header), 0, (SOCKADDR*)&ServerAddress, &ServerAddLen);
        // �������ж��Ƿ�ʱ
        if (clock() - time > WAITING_MAX) {
            // ��ʱ���ط�
            // cout << "��һ����λ�����Ϣ���䳬ʱ��" << endl;
            // cout << "�����ط���һ�λ�����Ϣ......" << endl;
            int send_len = sendto(ClientSocket, SendBuff, sizeof(header), 0, (SOCKADDR*)&ServerAddress, ServerAddLen);
            if (send_len < 0) {
                cout << "[client]:��һ�λ��ַ�������ʧ�ܣ�" << endl;
                break;
            }
            cout << "[client]:��һ�λ�����Ϣ���ͳɹ���" << endl;
            header.print();
            // �����������¼�ʱ
            time = clock();
            continue; // Ȼ������ȴ����յڶ��λ��ֵ���Ϣ
        }
        // û�г�ʱ
        if (recv_len < 0) {
            // cout << "[client]:�ڶ��λ�����Ϣ����ing......" << endl;
            continue;
        }
        memcpy(&header, RecvBuff, sizeof(header));
        // ������
        if (header.flag == ACK && header.ack == 1 && CheckError(&header, sizeof(header)) == true) {
            cout << "[client]:�ڶ��λ�����Ϣ���ճɹ���" << endl;
            break;// ����ѭ��
        }
        //cout << "�ڶ��λ������ݼ��鲻ͨ����" << endl;
        //cout << "�������½��յڶ��λ�����Ϣ......" << endl;
    }


    /**** ���յ����λ������� ****/
    header.reset();
    while (true) {
        int recv_len = recvfrom(ClientSocket, RecvBuff, sizeof(header), 0, (SOCKADDR*)&ServerAddress, &ServerAddLen);
        if (recv_len < 0) {
            // cout << " �����λ�����Ϣ����ing......" << endl;
            continue;
        }
        memcpy(&header, RecvBuff, sizeof(header));
        // ������
        if (header.flag == FIN && header.fin == 1 && CheckError(&header, sizeof(header)) == true) {
            cout << "[client]:�����λ�����Ϣ���ճɹ���" << endl;
            break;// ����ѭ��
        }
        //cout << "�����λ������ݼ��鲻ͨ����" << endl;
        //cout << "�������½��յ����λ�����Ϣ......" << endl;
    }



    /**** ������Ĵλ������� ****/
    // ��������ͷ��Ϣ
    header.reset();
    header.flag = ACK;
    header.ack = 2;// ���յ���2��3
    // ����α�ײ�������У���
    header.Checksum = Phead->Cal_Checksum(&header);

    // header�浽��������׼������
    //cout << "[client]:���Ĵλ�����Ϣ����ing......" << endl;
    memcpy(SendBuff, &header, sizeof(header));
    while (sendto(ClientSocket, SendBuff, sizeof(header), 0, (SOCKADDR*)&ServerAddress, ServerAddLen) == false) {
        // cout << "���Ĵλ��ַ�������ʧ�ܣ�" << endl;
        ;
    }
    cout << "[client]:���Ĵλ�����Ϣ���ͳɹ���" << endl;
    header.print();
    cout << "�ͻ��������������˳�" << endl;



}

int main() {
    // ��ʼ��
    init();

    cout << "�ͻ��˷������ӽ�������..." << endl;
    // �������ֽ�������
    if (ClientConnect() == -1) {
        cout << "��������ʧ�ܣ�" << endl;
    }

    cout << "�����봰�ڴ�С��" << endl;
    cin >> WindowSize;

    cout << "�����붪���ʣ�" << endl;
    cin >> Loss;

    cout << "��������ʱ��" << endl;
    cin >> timmer;

    cout << "/****** ������Ҫ������ļ����� ******/" << endl;
    cin >> figName;


    /**** ���������߳� ****/
    HANDLE handle_send = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)SendMessageThread, &ClientSocket, 0, 0);
    HANDLE handle_recv = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)RecvMessageThread, &ClientSocket, 0, 0);
    HANDLE handle_Resend = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)GBN_ReSendMessageThread, &ClientSocket, 0, 0);

    // ��ⷢ���߳��Ƿ����
    // �ȴ��߳̽���
    DWORD send_thred_result = WaitForSingleObject(handle_send, INFINITE);
    while (send_thred_result != WAIT_OBJECT_0)
        continue;

    CloseFlag = 1;

    // �Ĵλ��ֽ�������
    ClientCloseConnection();

    while (true) {
        break;
    }
    

    return 0;

}