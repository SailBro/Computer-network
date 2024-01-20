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

/**** һЩ��������****/
// IP��32λ���Ͷ˿ڣ�16λ��
const uint32_t SOURCE_IP = 2130706433;
const uint32_t DESTINATION_IP = 2130706433;
const uint16_t SOURCE_PORT = 8887;
const uint16_t DESTINATION_PORT = 8888;

string savePath;

/**** ȫ�ֱ�������****/
// �׽���
SOCKET ServerSocket;
// ��ַ
SOCKADDR_IN ServerAddress;
SOCKADDR_IN ClientAddress;
int ServerAddLen;
int ClientAddLen;
WSADATA wsaData;

// �洢data�����飨char*���ͣ��ͻ�����һ����
char* RecvData;
int timmer=20;

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
        else if (flag == FIN_ACK)
            cout << "flag:FIN,ACK  fin:" << fin << "  ack:" << ack << "  Checksum  " << Checksum << endl;
        else if (flag == SEQ)
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
            //  << res << " ";
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

// �������˳�ʼ��
void init() {
    // ��ʼ���׽���
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    // ���÷������˵�ַ
    ServerAddress.sin_family = AF_INET;
    ServerAddress.sin_addr.s_addr = htonl(2130706433);
    ServerAddress.sin_port = htons(8887);

    // ���ÿͻ��˵�ַ
    ClientAddress.sin_family = AF_INET;
    ClientAddress.sin_addr.s_addr = htonl(2130706433);
    ClientAddress.sin_port = htons(8888);

    // // ����·�����ĵ�ַ
    // RouterAddress.sin_family = AF_INET;
    // RouterAddress.sin_addr.s_addr = htonl(0x7f01);
    // RouterAddress.sin_port = htond(8888);

    // �󶨷����
    ServerSocket = socket(AF_INET, SOCK_DGRAM, 0);
    int bind_res = bind(ServerSocket, (sockaddr*)&ServerAddress, sizeof(ServerAddress));
    if (bind_res == SOCKET_ERROR) {
        cout << "server: bind failed." << endl;
    }

    unsigned long on = 1;
    ioctlsocket(ServerSocket, FIONBIO, &on);

    ClientAddLen = sizeof(ClientAddress);
    ServerAddLen = sizeof(ServerAddress);

    cout << "�������˳�ʼ����ɣ�" << endl;
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

// �������ֽ�������
int ServerConnect() {
    // 1��3���������գ�2����������
    Header header;
    // ����������
    char* RecvBuff = new char[1000];
    char* SendBuff = new char[1000];
    cout << "��������ʼ�ȴ�����......" << endl;

    /**** ��һ������ ****/
    cout << "[server]:�ȴ���һ������..." << endl;
    while (true) {
        // ͨ��recvfrom�������ձ��ģ���һ�����ַ�����ֻ������ͷ
        int recv_len = recvfrom(ServerSocket, RecvBuff, sizeof(header), 0, (sockaddr*)&ClientAddress, &ClientAddLen);
        if (recv_len < 0) {
            // cout << "��һ�����ֽ���ing......" << endl;
            continue;
        }
        // ���յ���Ϣ�󣬸�header��ֵ����ȡ
        memcpy(&header, RecvBuff, sizeof(header));
        // cout << header.flag << endl;

        // ��header���в�����
        if (header.flag == SYN && CheckError(&header, sizeof(header)) == true) {
            cout << "[server]:��һ��������Ϣ���ճɹ���" << endl;
            break;// ����ѭ��
        }
        //cout << "��һ���������ݼ��鲻ͨ����" << endl;
        //cout << "�������½��յ�һ��������Ϣ......" << endl;
    }


    /**** ����ڶ������� ****/
    // ����header���޸���Ϣ��
    header.reset();
    header.flag = SYN_ACK;
    header.ack = 1;
    // ����α�ײ�������У���
    PseudoHeader* Phead = new PseudoHeader();
    header.Checksum = Phead->Cal_Checksum(&header);

    // header�浽��������׼������
    memcpy(SendBuff, &header, sizeof(header));
    while (sendto(ServerSocket, SendBuff, sizeof(header), 0, (SOCKADDR*)&ClientAddress, ClientAddLen) == false) {
        // cout << "�ڶ������ַ�������ʧ�ܣ�" << endl;
        ;
    }
    cout << "[server]:�ڶ���������Ϣ���ͳɹ���" << endl;
    header.print();

    /**** ���յ��������� ****/
    // ͨ��whileѭ���ȴ����տͻ��˷�������Ϣ����ʱ����Ҫ�ش��ڶ�������
    // ��ʼ��ʱ
    header.reset();
    clock_t time = clock();
    while (true) {
        int recv_len = recvfrom(ServerSocket, RecvBuff, sizeof(header), 0, (sockaddr*)&ClientAddress, &ClientAddLen);
        // һֱû���յ�
        if (clock() - time > WAITING_MAX) {
            // cout << "�ڶ�������������Ϣ���䳬ʱ��" << endl;
            // cout << "�����ط��ڶ���������Ϣ......" << endl;
            int send_len = sendto(ServerSocket, SendBuff, sizeof(header), 0, (SOCKADDR*)&ClientAddress, ClientAddLen);
            if (send_len < 0) {
                cout << "[server]:�ڶ������ַ�������ʧ�ܣ�" << endl;
                return -1;
            }
            cout << "[server]:�ڶ���������Ϣ���ͳɹ���" << endl;
            header.print();
            // �����������¼�ʱ
            time = clock();
            continue; // Ȼ������ȴ����յ��������ֵ���Ϣ
        }
        // û�г�ʱ�Ļ�
        if (recv_len < 0) {
            // cout << "������������Ϣ����ing......" << endl;
            // cout<< WSAGetLastError() << endl;
            continue;
        }
        // ���յ���Ϣ�󣬸�header��ֵ����ȡ
        memcpy(&header, RecvBuff, sizeof(header));
        // ��header���в�����
        if (header.flag == ACK && header.ack == 1 && CheckError(&header, sizeof(header)) == true) {
            cout << "[server]:������������Ϣ���ճɹ���" << endl;
            break;// ����ѭ��
        }
        //cout << "�������������ݼ��鲻ͨ����" << endl;
        //cout << "�������½��յ�����������Ϣ......" << endl;
    }

    // ���ֳɹ���
    //cout << "���������ֳɹ���" << endl;
    cout << "[server]:�ȴ���������ing......" << endl;
    return 1;

}

void RecvMessage() {
    // �Ƚ�������ͷ���ͻ�����
    Header header;
    header.flag = ACK;
    // һ��ʼseq��ack��Ϊ0
    char* RecvBuff = new char[sizeof(header) + DATA_LEN_MAX];
    char* SendBuff = new char[sizeof(header)];
    // data���
    RecvData = new char[DATA_ALL];

    // ͨ��whileѭ��ʵ�ֶԷ���0��1�ĵݹ����
    int TempGroup = 0;
    unsigned long long int ByteNum = 0;
    int pckNum = 0;
    while (true) {
        // Sleep(300);
        // һ��ѭ�����Ƚ���
        header.reset();
        int recv_len = recvfrom(ServerSocket, RecvBuff, sizeof(header) + DATA_LEN_MAX, 0, (sockaddr*)&ClientAddress, &ClientAddLen);
        if (recv_len < 0)
            continue;
        // ���ĳ��Ȳ�Ϊ0ʱ��ͷ����ֵ��head�������в����
        memcpy(&header, RecvBuff, sizeof(header));
        if (CheckError(&header, sizeof(header)) == false || header.seq != TempGroup) {
            // cout << "[server]:����" << TempGroup << "�����ݱ�����ʧ�ܣ�" << endl;8
            // ��Ҫ������һ�εı���
            TempGroup = (TempGroup + 1) % 2; // 0/1�û�
            // SendBuffû�б�
            while (sendto(ServerSocket, SendBuff, sizeof(header), 0, (SOCKADDR*)&ClientAddress, ClientAddLen) < 0) {
                ;
            }
            // continue; // �ȴ��ش�������Ack0���ᳬʱ����һ��ѭ�����Ǳ���0
        }
        cout << "[server]:����" << TempGroup << "���������ݱ�["<< pckNum++ <<"]���ճɹ���" << endl;

        // ���ճɹ�������data��������Ack
        // �ȼ��һ���ǲ���over�������ˣ�
        if (header.flag == OVER) {
            cout << "[server]:��ʼ����������ȫ�����ݰ�......" << endl;
            RecvData[ByteNum] = '\0';
            string path =  "D:\\test_code\\computer-network\\server\\"+savePath;
            // �����
            ofstream os(path.c_str(), ofstream::binary);
            for (int i = 0;i < ByteNum;i++)
                os << RecvData[i];
            os.close();
            return;
        }
        else {
            // �����������ݵ�data���У���ByteNum��ʼ��
            memcpy(RecvData + ByteNum, RecvBuff + sizeof(header), recv_len - sizeof(header));
            ByteNum += recv_len - sizeof(header); // ������ȥ��ͷ������
        }

        // ���ն���ʱ��һ�㶼���ٶȣ���>�գ�
        Sleep(timmer);
        header.reset();
        header.ack = TempGroup; // ȷ���յ�����
        header.flag = ACK;
        // ����У��λ
        PseudoHeader* Phead = new PseudoHeader();
        header.Checksum = Phead->Cal_Checksum(&header);
        memcpy(SendBuff, &header, sizeof(header));
        while (sendto(ServerSocket, SendBuff, sizeof(header), 0, (SOCKADDR*)&ClientAddress, ClientAddLen) < 0) {
            // cout << "����" << TempGroup << "��Ack����ʧ�ܣ�" << endl;
        }
        header.print();
        // �ȴ���һ��
        TempGroup = (TempGroup + 1) % 2; // 0/1�û�
        cout << "[server]:�ȴ�����" << TempGroup << "����������......" << endl;
    }

}

// �Ĵλ��ֵĽ��շ����ر�����
void ServerCloseConnection() {
    Header header;
    char* RecvBuff = new char[1000];
    char* SendBuff = new char[1000];

    /**** �ȴ���һ�λ������� ****/
    while (true) {
        int recv_len = recvfrom(ServerSocket, RecvBuff, sizeof(header), 0, (SOCKADDR*)&ClientAddress, &ClientAddLen);
        if (recv_len < 0) {
            //cout << "��һ�λ�������ȴ�ing" << endl;
            continue;
        }
        // ���յ���Ϣ�󣬸�header��ֵ����ȡ
        memcpy(&header, RecvBuff, sizeof(header));
        // ��header���в�����
        if (header.flag == FIN_ACK && header.fin == 1 && CheckError(&header, sizeof(header)) == true) {
            cout << "[server]:��һ�λ�����Ϣ���ճɹ���" << endl;
            break;// ����ѭ��
        }
        //cout << "��һ�λ������ݼ��鲻ͨ����" << endl;
        //cout << "�������½��յ�һ�λ�����Ϣ......" << endl;
    }

    /**** ����ڶ��λ��� ****/
    // ���޸�header����Ϣ
    header.reset();
    header.flag = ACK;
    header.ack = 1;
    // ����α�ײ���У��
    PseudoHeader* Phead = new PseudoHeader();
    header.Checksum = Phead->Cal_Checksum(&header);
    // װ�����ͻ�����
    memcpy(SendBuff, &header, sizeof(header));
    // ��ʼ���Ͳ���ʱ
    while (sendto(ServerSocket, SendBuff, sizeof(header), 0, (SOCKADDR*)&ClientAddress, ClientAddLen) < 0) {
        // cout << "�ڶ��λ�����Ϣ����ing......" << endl;
        ;
    }
    cout << "[server]:�ڶ��λ�����Ϣ���ͳɹ���" << endl;
    header.print();

    /**** ���͵����λ�����Ϣ ****/
    // ���޸�ͷ
    header.reset();
    header.flag = FIN;
    header.ack = 1;// ֻ�յ�һ��
    header.fin = 1;// ҲҪ�ر���
    // α�ײ�У��
    header.Checksum = Phead->Cal_Checksum(&header);
    // װ�����ͻ�����
    memcpy(SendBuff, &header, sizeof(header));
    // ��ʼ���Ͳ���ʱ
    while (sendto(ServerSocket, SendBuff, sizeof(header), 0, (SOCKADDR*)&ClientAddress, ClientAddLen) < 0) {
        // cout << "�����λ�����Ϣ����ing......" << endl;
        ;
    }
    cout << "[server]:�����λ�����Ϣ���ͳɹ���" << endl;
    header.print();

    /**** ���յ��Ĵλ��� ****/
    header.reset();
    clock_t time = clock();
    while (true) {
        int recv_len = recvfrom(ServerSocket, RecvBuff, sizeof(header), 0, (SOCKADDR*)&ClientAddress, &ClientAddLen);
        if (recv_len < 0) {
            // cout << "���Ĵλ�����Ϣ����ing......" << endl;
            continue;
        }
        // ������ɹ�������
        memcpy(&header, RecvBuff, sizeof(header));
        // ������
        if (header.flag == ACK && header.ack == 2 && CheckError(&header, sizeof(header)) == true) {
            cout << "[server]:���Ĵλ�����Ϣ���ճɹ���" << endl;
            break;// ����ѭ��
        }
        //cout << "���Ĵλ������ݼ��鲻ͨ����" << endl;
        //cout << "�������½��յ��Ĵλ�����Ϣ......" << endl;
    }

    // ���ֽ���
    cout << "�������������������˳�" << endl;
    Sleep(timmer);


}



// �������˵�������
int main() {
    // ��ʼ��
    init();


    // �������ֽ�������
    int connect_res = ServerConnect();
    if (connect_res == -1) {
        cout << "��Warning:�����ӽ���ʧ�ܣ������������رգ�" << endl;
        Sleep(50);
        return -1;
    }

    cout << "������ʱ" << endl;
    cin >> timmer;

    cout << "���뱣���ļ�����" << endl;
    cin >> savePath;

    // ���ݴ���
    RecvMessage();

    // �Ĵλ��ֽ�������
    ServerCloseConnection();

    while (true) {
        ;
    }

    return 0;

}








