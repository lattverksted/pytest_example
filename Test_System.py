import pytest
#import cantools

fname1 = "CANDump1.log"
fname2 = "CANDump2.log"

# read log files and returns test candumps
@pytest.fixture
def candumps():
    f1 = open(fname1, 'r')
    f2 = open(fname2, 'r')
    lines1 = f1.readlines()
    lines2 = f2.readlines()
    return lines1, lines2

# get CAN ID from frame
def canID(frame) :
    useful_info = frame.split(" ")[-1]
    return useful_info.split("#")[0]

# get DATA from CAN frame
def data(frame) :
    useful_info = frame.split(" ")[-1]
    return useful_info.split("#")[1].strip("\n")


# check file has a proper structure
def test_logfile_structure (candumps):
    for candump in candumps:
        for line in candump:
            elements = line.split(" ")
            assert len(elements) == 3, "log file DOES NOT have the right structure {}".format(line)

            useful_info = elements[-1].split('#')
            assert len(useful_info) == 2, "log file DOES NOT have the right structure {}".format(line)

#get PDU Format from CAN ID
def pdu_decimal(can_id):
    str_pdu = can_id[2:4]
    return int(str_pdu,16)

# test the above method is correct
def test_pdu_decimal() :
    assert pdu_decimal("11010203") == 0x01
    assert pdu_decimal("11145415") == 0x14

# get destination address from CAN ID
def dst_addr(can_id) :
    str_dst_addr = can_id[4:6]
    return int(str_dst_addr,16)


# test the above method is correct
def test_dst_addr() :
    assert dst_addr("11020203") == 0x02
    assert dst_addr("11025415") == 0x54

# get source address from CAN ID
def src_addr(can_id) :
    str_src_addr = can_id[6:]
    return int(str_src_addr,16)

# test the above method  is correct
def test_src_addr() :
    assert src_addr("11020203") == 0x03
    assert src_addr("11020215") == 0x15

# get message priority from CAN ID
def priority(can_id) :
    str_p = can_id[:2]
    return int(str_p, 16)

# test the above method priority is correct
def test_priority() :
    assert priority("11020203") == 0x11
    assert priority("14020203") == 0x14

# computes nozzle number using byte number and n from PDU number
def nozzle_number(n, byte):
    return (n-1)*8 + byte + 1

# test the above method nozzle_number  is correct
def test_nozzle_number() :
    assert nozzle_number(0x01,0) == 1
    assert nozzle_number(0x01,5) == 6
    assert nozzle_number(0x0D,3) == 100

# check CAN message ID is correct

# check PDU format is <=0x14
def test_PDUFormatUpperRange(candumps) :

    for candump in candumps :
        for line in candump:
            pdu_dec = pdu_decimal(canID(line))

            assert pdu_dec<=0x14, "PDU out of Range {} : > 0x14\n {}".format(pdu_dec, line)

# check PDU Format >=1
def test_PDUFormatLowerRange(candumps) :
    for candump in candumps :
        for line in candump:
            pdu_dec = pdu_decimal(canID(line))
    
            assert pdu_dec>=0x01, "PDU out of Range {} : < 0x01 \n {}".format(pdu_dec, line )

# check destination address is 0x02
def test_DestinationAddressIs0x02(candumps):

    for candump in candumps :
        for line in candump:

            dest_addr = dst_addr( canID(line))
            assert dest_addr == 0x02, "destination_address IS NOT 0x02  but {}\n {} ".format(dest_addr, line)

# check source address is 0x03
def test_SourceAddressIs0x03(candumps):

    for candump in candumps :
        for line in candump:

            source_addr = src_addr( canID(line))
            assert source_addr == 0x03, "source_address IS NOT 0x03  but {} \n {}".format(source_addr, line)

# check CAN ID is a 29 bits numbers
def testCanIdIs29bits(candumps):
    for candump in candumps :
        for line in candump:

            int_can_id = int(canID(line),16)
            assert int_can_id <= 0x1FFFFFFF, "source_address IS NOT 29 bits  {} \n {}".format(int_can_id, line)

# check message priority is 0x11
def test_PriorityIs0x011(candumps):
    for candump in candumps:
        for line in candump:
            p = priority(canID(line))
            assert p == 0x11, "priority IS NOT 0x11  but {} \n{}".format(p,line)



# check CAN messages send orders to existing Nozzles ID
# check nozzle number is smaller than 150
def test_NozzleNumberSmallerThan150(candumps):
    for candump in candumps:
        for line in candump:
            n = pdu_decimal(canID(line))
            msg = data(line)
            # for every non-null byte
            for b in range(8) :

                byte_str = msg[2 * b:2 * b + 2]
                if byte_str != "00":

                    nozzle = nozzle_number(n, b)
                    assert nozzle <=150,"nozzle number >150 {} \n{}".format(nozzle,msg)

# check nozzle number is greater than 1
def test_NozzleNumberGreaterThan1(candumps):
    for candump in candumps:
        for line in candump:
            n = pdu_decimal(canID(line))
            msg = data(line)
            # for every non-null byte
            for b in range(8):

                byte_str = msg[2 * b:2 * b + 2]
                if byte_str != "00":

                    nozzle = nozzle_number(n, b)
                    assert nozzle >=1 ,"nozzle number <1 {} \n{}".format(nozzle,msg)


# check message data length is 8
def test_MessageLengthIs8Bytes(candumps):
    for candump in candumps:
        for line in candump:
            data_length = len(data(line))
            assert data_length == 16, "data length IS NOT 8 bytes  but {} chars \n{} \n {}".format(data_length , line, data(line))

# test if string only contains hexadecimal characters
def OnlyContainsHexadecimalDigits(str):
    allowed = {'0','1','2','3','4','5','6','7','8','9', 'A', 'B', 'C', 'D', 'E', 'F'}
    for c in str:
        # Check if the character
        # is invalid
         if c not in allowed:
             return False
    return True
# test above function
def test_OnlyContainsHexadecimalDigits():

    assert OnlyContainsHexadecimalDigits("0123456789ABCDEF") == True
    assert OnlyContainsHexadecimalDigits("000000000111111X") == False
    assert OnlyContainsHexadecimalDigits("00000000ù%&;") == False

# check CAN ID only contains hexadecimal digits
def test_CanIdOnlyContainsHexadecimalDigits(candumps) :
    for candump in candumps:
        for frame in candump:
            can_id = canID(frame)

            assert OnlyContainsHexadecimalDigits(can_id) == True, " is NOT hexadecimal. It contains \n{} in \n {}".format(can_id,
                                                                                               frame)


# check DATA only contains hexadecimal digits
def test_DataOnlyContainsHexadecimalDigits(candumps) :
    for candump in candumps:
        for frame in candump:
            msg = data(frame)
            assert OnlyContainsHexadecimalDigits(msg) == True, " is NOT hexadecimal. It contains \n{} in \n {}".format(
            msg,
            frame)

# check in a byte if At Least One Herbicide Type Is Set To 1 assuming An Opening Command
def checkByteOpeningCommand(byte):

        mask = 0b00110001
        byte_masked = byte & mask
        return byte_masked != 0b00000001

# test the above function
def test_checkByteOpeningCommand():
    assert checkByteOpeningCommand(0b00000001) == False
    assert checkByteOpeningCommand(0b00100001) == True
    assert checkByteOpeningCommand(0b00010001) == True
    assert checkByteOpeningCommand(0b00110001) == True
    assert checkByteOpeningCommand(3) == False


# check that at least one herbicide type is set to 1 when sending an opening command
def test_AtLeastOneHerbicideTypeIsSetTo1WhenSendingAnOpeningCommand(candumps):
    for candump in candumps:
        for frame in candump:
            frame_data = data(frame)
            # for every non-null byte
            for b in range(8):

                byte_str = frame_data[2 * b:2 * b + 2]
                if byte_str !="00" :  #  non null bytes

                    try:
                        int_byte = int(byte_str, 16)
                    except ValueError:
                        continue
                    #if opening command
                    if int_byte % 2 == 1:
                        assert checkByteOpeningCommand(int_byte)==True , "Opening command with no herbicide Type set to 1 :\n{} in \n {}".format(byte_str,frame)

# check in a byte if No Herbicide Type Is Set To 1 assuming An Closing Command
def checkByteClosingCommand(byte):

        mask = 0b00110001
        byte_masked = byte & mask
        return byte_masked == 0b00000000

# test the above function
def test_checkByteClosingCommand():
    assert checkByteClosingCommand(0b00000000) == True
    assert checkByteClosingCommand(0b00100000) == False
    assert checkByteClosingCommand(0b00010000) == False
    assert checkByteClosingCommand(0b00110000) == False


# check that no herbicide type is set to 1 when sending a closing command
def test_NoHerbicideTypeIsSetTo1WhenSendingAClosingCommand(candumps):
    for candump in candumps:
        for frame in candump:
            frame_data = data(frame)
            # for every byte
            for b in range(8):

                byte_str = frame_data[2 * b:2 * b + 2]
                if byte_str != "00":  # non null bytes

                    try:
                        int_byte = int(byte_str, 16)
                    except ValueError:
                        continue
                    # if closing command
                    if int_byte % 2 == 0:
                        assert checkByteClosingCommand(int_byte) == True, "Closing command with one herbicide Type set to 1 :\n{} in \n {}".format(byte_str, frame)


# check reserved bits are always set to zero
def test_ReservedBitsAreAlwaysSetToZero(candumps):
    for candump in candumps:
        for frame in candump:
            frame_data = data(frame)
            try:
                msg = int(frame_data, 16)
            except ValueError:
                continue
            mask_reserved_bits = 0b11001110
            msg_masked_reserved_bits = msg & mask_reserved_bits
            assert msg_masked_reserved_bits == 0 , "all reserved are NOT 0 but decimal  \n{} in \n {}".format( msg_masked_reserved_bits,
                                                                                                   frame)




