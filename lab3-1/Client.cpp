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
        memcpy(buf + sizeof(*head), &SourceIp, sizeof(SourceIp));
        memcpy(buf + sizeof(*head) + sizeof(SourceIp), &DestIp, sizeof(DestIp));
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

void SendMessage() {
    // �Ƚ�������ͷ���ͻ�����
    Header header;
    PseudoHeader* Phead = new PseudoHeader();
    header.flag = SEQ;
    // һ��ʼseq��ack��Ϊ0
    char* RecvBuff = new char[sizeof(header)];
    char* SendBuff = new char[sizeof(header) + DATA_LEN_MAX];
    // data���
    SendData = new char[DATA_ALL];


    /**** �������� ****/
    cout << "/****** ������Ҫ������ļ����� ******/" << endl;
    string figName;
    cin >> figName;
    // ���ļ�
    ifstream is("file//"+figName, ifstream::binary);
    // ��server�˲�ͬ���ǲ�֪���ļ���С��ֻ��һ��һ������
    unsigned long long int ByteNum = 0;
    unsigned char temp = is.get();
    while (is) {
        SendData[ByteNum++] = temp;
        temp = is.get();
    }
    cout << "[client]:�ļ��Ѿ��ɹ����룬��СΪ" << ByteNum << "�ֽ�" << endl;
    is.close();

    /**** �������� ****/
    // ֻ��0��1
    // �ȼ���һ��Ҫ�����ٴΣ�Ȼ�����ö�����
    int tally = ByteNum / DATA_LEN_MAX+1;
    cout << "[client]:�ļ�������ֳ�" << tally << "�������д���" << endl;
    int TempGroup = 0;// �ӷ���0��ʼ����
    unsigned long long int TempByte = 0;// �Ѿ������ȥ���ֽ�����
    clock_t time = clock();// �����
    int TempTally = 0;//�Ѿ�����ȥ�İ���
    int loss_pck = 0;
    int count_pck = tally * Loss;
    clock_t begin = clock();

    while (true) {
        // ÿ�ν�ѭ����Ҫ�Ƚ��������ݴ����������
        header.reset();
        header.flag = SEQ;
        header.seq = TempGroup; // �����кż�¼
        header.Checksum = Phead->Cal_Checksum(&header);
        // ���һ�η�ʣ�µ�
        int Templen = (TempTally == tally - 1) ? ByteNum - TempByte : DATA_LEN_MAX;
        // �Ȱ����ݱ�ͷ���뻺�������ٷ���Data
        memcpy(SendBuff, &header, sizeof(header));
        memcpy(SendBuff + sizeof(header), SendData + TempByte, Templen);
        // ÿ10��������
        if (TempTally % count_pck == 1) {
            cout << "[client]:����" << TempGroup << "����[" << TempTally << "]����......" << endl;
            time = clock();
            //��ʱ��
            // Sleep(3000);// �ȴ���Ӧ��ʱ��϶���ʱ

            //while (sendto(ClientSocket, SendBuff, sizeof(header) + Templen, 0, (SOCKADDR*)&ServerAddress, ServerAddLen) < 0)
            //    ;//cout << WSAGetLastError() << endl;
            //cout << "[client]:�ɹ����ͷ���" << TempGroup << "�����ݰ�[" << TempTally << "]��" << endl;
            //time = clock();
        }
        else {// ������
            while (sendto(ClientSocket, SendBuff, sizeof(header) + Templen, 0, (SOCKADDR*)&ServerAddress, ServerAddLen) < 0)
                ;//cout << WSAGetLastError() << endl;
            cout << "[client]:�ɹ����ͷ���" << TempGroup << "�����ݰ�[" << TempTally << "]��" << endl;
            header.print();
            time = clock();
        }
        // Ȼ��ȴ���Ӧ
        // ����Ϳ�ʼ��ʱ
        while (true) {
            header.reset();
            if (clock() - time > WAITING_MAX) {
                cout<<"[client]:����" << TempGroup << "�����ݰ�[" << TempTally  << "]��ʱ���������·���......" << endl;
                loss_pck++;// ������++
                while (sendto(ClientSocket, SendBuff, sizeof(header) + Templen, 0, (SOCKADDR*)&ServerAddress, ServerAddLen) < 0)
                    ;//cout << WSAGetLastError() << endl;
                cout << "[client]:�ɹ����ͷ���" << TempGroup << "�����ݰ�[" << TempTally << "]��" << endl;
                header.print();
                // �ǵ����¼�ʱ������
                time = clock();
            }
            // cout << "!" << endl;
            int recv_len = recvfrom(ClientSocket, RecvBuff, sizeof(header), 0, (SOCKADDR*)&ServerAddress, &ServerAddLen);
            // cout << WSAGetLastError();
            // cout << TempTally << endl;
            if (recv_len < 0)
                continue;
            // ���յ��˽���ȷ��
            memcpy(&header, RecvBuff, sizeof(header));
            if (header.ack == TempGroup && CheckError(&header, sizeof(header)) == true) {
                // ȷ�����ٸ�TempTally++
                cout << "[client]:��ȷ�Ϸ���" << TempGroup << "�����ݰ�[" << TempTally++ << "]���ͳɹ���" << endl;
                TempByte += Templen;
                cout << "tempBtye" << TempByte << endl;
                break;
            }   
        }
        // Ȼ�������һ��
        if (TempTally >= tally) {
            cout << "[client]:ȫ�����ݰ��������......" << endl;
            break;
        }
        // �޸���Ϣ
        TempGroup = (TempGroup + 1) % 2;
        // ��ʱ�ȴ�һ����ٷ���һ��
    }


    // ���ͽ����ı���OVER=1
    header.reset();
    header.seq = (TempGroup + 1) % 2;// ������Ҫ��һ����������
    header.flag = OVER;
    header.Checksum = Phead->Cal_Checksum(&header);
    memcpy(SendBuff, &header, sizeof(header));
    while (sendto(ClientSocket, SendBuff, sizeof(header), 0, (SOCKADDR*)&ServerAddress, ServerAddLen) < 0)
        ;

    // ���Ͷ˼�����ʱ��������
    clock_t time_total = clock() - begin;
    double seed = (double)ByteNum / time_total;
    double loss = (double)loss_pck / tally;
    cout << "/************************************************************/" << endl;
    cout << "[client]:���δ��乲����" << ByteNum << "���ֽڣ�" << tally << "�����ݰ�" << endl;
    cout << "    ��ʱ:" << time_total << "ms" << endl;
    cout << "    ������:" << seed << " Byte / ms"<<endl;

    cout << "[client]:����ر�......" << endl;




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

    cout << "�����붪���ʣ�" << endl;
    cin >> Loss;

    // ���ݴ���
    SendMessage();

    // �Ĵλ��ֽ�������
    ClientCloseConnection();

    while (true) {
        ;
    }
    

    return 0;

}