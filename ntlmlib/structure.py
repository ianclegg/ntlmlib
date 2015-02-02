# (c) 2015, Ian Clegg <ian.clegg@sourcewarp.com>
#
# ntlmlib is licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
__author__ = 'ian.clegg@sourcewarp.com'

from struct import pack, unpack, calcsize


class Structure:
    """ sublcasses can define commonHdr and/or structure.
        each of them is an tuple of either two: (fieldName, format) or three: (fieldName, ':', class) fields.
        [it can't be a dictionary, because order is important]
        
        where format specifies how the data in the field will be converted to/from bytes (string)
        class is the class to use when unpacking ':' fields.

        each field can only contain one value (or an array of values for *)
           i.e. struct.pack('Hl',1,2) is valid, but format specifier 'Hl' is not (you must use 2 dfferent fields)

        format specifiers:
          specifiers from module pack can be used with the same format 
          see struct.__doc__ (pack/unpack is finally called)
            x       [padding byte]
            c       [character]
            b       [signed byte]
            B       [unsigned byte]
            h       [signed short]
            H       [unsigned short]
            l       [signed long]
            L       [unsigned long]
            i       [signed integer]
            I       [unsigned integer]
            q       [signed long long (quad)]
            Q       [unsigned long long (quad)]
            s       [string (array of chars), must be preceded with length in format specifier, padded with zeros]
            p       [pascal string (includes byte count), must be preceded with length in format specifier, padded with zeros]
            f       [float]
            d       [double]
            =       [native byte ordering, size and alignment]
            @       [native byte ordering, standard size and alignment]
            !       [network byte ordering]
            <       [little endian]
            >       [big endian]

          usual printf like specifiers can be used (if started with %) 
          [not recommeneded, there is no why to unpack this]

            %08x    will output an 8 bytes hex
            %s      will output a string
            %s\\x00  will output a NUL terminated string
            %d%d    will output 2 decimal digits (against the very same specification of Structure)
            ...

          some additional format specifiers:
            :       just copy the bytes from the field into the output string (input may be string, other structure, or anything responding to __str__()) (for unpacking, all what's left is returned)
            z       same as :, but adds a NUL byte at the end (asciiz) (for unpacking the first NUL byte is used as terminator)  [asciiz string]
            u       same as z, but adds two NUL bytes at the end (after padding to an even size with NULs). (same for unpacking) [unicode string]
            w       DCE-RPC/NDR string (it's a macro for [  '<L=(len(field)+1)/2','"\\x00\\x00\\x00\\x00','<L=(len(field)+1)/2',':' ]
            ?-field length of field named 'field', formated as specified with ? ('?' may be '!H' for example). The input value overrides the real length
            ?1*?2   array of elements. Each formated as '?2', the number of elements in the array is stored as specified by '?1' (?1 is optional, or can also be a constant (number), for unpacking)
            'xxxx   literal xxxx (field's value doesn't change the output. quotes must not be closed or escaped)
            "xxxx   literal xxxx (field's value doesn't change the output. quotes must not be closed or escaped)
            _       will not pack the field. Accepts a third argument, which is an unpack code. See _Test_UnpackCode for an example
            ?=packcode  will evaluate packcode in the context of the structure, and pack the result as specified by ?. Unpacking is made plain
            ?&fieldname "Address of field fieldname".
                        For packing it will simply pack the id() of fieldname. Or use 0 if fieldname doesn't exists.
                        For unpacking, it's used to know weather fieldname has to be unpacked or not, i.e. by adding a & field you turn another field (fieldname) in an optional field.
            
    """
    common_header = ()
    structure = ()
    debug = 0

    def __init__(self, data=None, alignment=0):
        if not hasattr(self, 'alignment'):
            self.alignment = alignment

        self.fields = {}
        self.rawData = data
        if data is not None:
            self.from_string(data)
        else:
            self.data = None

    @classmethod
    def from_file(cls, file_object):
        answer = cls()
        answer.from_string(file_object.read(len(answer)))
        return answer

    def set_alignment(self, alignment):
        self.alignment = alignment

    def set_data(self, data):
        self.data = data

    def pack_field(self, field_name, field_format=None):
        if self.debug:
            print "pack_field( %s | %s )" % (field_name, field_format)

        if field_format is None:
            field_format = self.format_for_field(field_name)

        if field_name in self.fields:
            ans = self.pack(field_format, self.fields[field_name], field=field_name)
        else:
            ans = self.pack(field_format, None, field=field_name)

        if self.debug:
            print "\t answer %r" % ans

        return ans

    def get_data(self):
        if self.data is not None:
            return self.data
        data = ''
        for field in self.common_header + self.structure:
            try:
                data += self.pack_field(field[0], field[1])
            except Exception, e:
                if field[0] in self.fields:
                    e.args += ("When packing field '%s | %s | %r' in %s" % (field[0], field[1], self[field[0]],
                                                                            self.__class__),)
                else:
                    e.args += ("When packing field '%s | %s' in %s" % (field[0], field[1], self.__class__),)
                raise
            if self.alignment:
                if len(data) % self.alignment:
                    data += ('\x00' * self.alignment)[:-(len(data) % self.alignment)]
            
        #if len(data) % self.alignment: data += ('\x00'*self.alignment)[:-(len(data) % self.alignment)]
        return data

    def from_string(self, data):
        self.rawData = data
        for field in self.common_header + self.structure:
            if self.debug:
                print "from_string( %s | %s | %r )" % (field[0], field[1], data)
            size = self.calc_unpack_size(field[1], data, field[0])
            if self.debug:
                print "  size = %d" % size
            data_class_or_code = str
            if len(field) > 2:
                data_class_or_code = field[2]
            try:
                self[field[0]] = self.unpack(field[1], data[:size], data_class_or_code=data_class_or_code,
                                             field=field[0])
            except Exception, e:
                e.args += ("When unpacking field '%s | %s | %r[:%d]'" % (field[0], field[1], data, size),)
                raise

            size = self.calcPackSize(field[1], self[field[0]], field[0])
            if self.alignment and size % self.alignment:
                size += self.alignment - (size % self.alignment)
            data = data[size:]

        return self
        
    def __setitem__(self, key, value):
        self.fields[key] = value
        self.data = None        # force recompute

    def __getitem__(self, key):
        return self.fields[key]

    def __delitem__(self, key):
        del self.fields[key]
        
    def __str__(self):
        return self.get_data()

    def __len__(self):
        # XXX: improve
        return len(self.get_data())

    def pack(self, field_format, data, field=None):
        if self.debug:
            print "  pack( %s | %r | %s)" % (field_format, data, field)

        if field:
            address_field = self.find_address_field_for(field)
            if (address_field is not None) and (data is None):
                return ''

        # void specifier
        if field_format[:1] == '_':
            return ''

        # quote specifier
        if field_format[:1] == "'" or field_format[:1] == '"':
            return field_format[1:]

        # code specifier
        two = field_format.split('=')
        if len(two) >= 2:
            try:
                return self.pack(two[0], data)
            except:
                fields = {'self': self}
                fields.update(self.fields)
                return self.pack(two[0], eval(two[1], {}, fields))

        # address specifier
        two = field_format.split('&')
        if len(two) == 2:
            try:
                return self.pack(two[0], data)
            except:
                if (self.fields.has_key(two[1])) and (self[two[1]] is not None):
                    return self.pack(two[0], id(self[two[1]]) & ((1 << (calcsize(two[0]) * 8)) - 1))
                else:
                    return self.pack(two[0], 0)

        # length specifier
        two = field_format.split('-')
        if len(two) == 2:
            try:
                return self.pack(two[0], data)
            except:
                return self.pack(two[0], self.calc_pack_field_size(two[1]))

        # array specifier
        two = field_format.split('*')
        if len(two) == 2:
            answer = ''
            for each in data:
                answer += self.pack(two[1], each)
            if two[0]:
                if two[0].isdigit():
                    if int(two[0]) != len(data):
                        raise Exception, "Array field has a constant size, and it doesn't match the actual value"
                else:
                    return self.pack(two[0], len(data)) + answer
            return answer

        # "printf" string specifier
        if field_format[:1] == '%':
            # format string like specifier
            return format % data

        # asciiz specifier
        if field_format[:1] == 'z':
            return str(data) + '\0'

        # unicode specifier
        if field_format[:1] == 'u':
            return str(data) + '\0\0' + (len(data) & 1 and '\0' or '')

        # DCE-RPC/NDR string specifier
        if field_format[:1] == 'w':
            if len(data) == 0:
                data = '\0\0'
            elif len(data) % 2:
                data += '\0'
            l = pack('<L', len(data) / 2)
            return '%s\0\0\0\0%s%s' % (l, l, data)
                    
        if data is None:
            raise Exception("Trying to pack None")
        
        # literal specifier
        if field_format[:1] == ':':
            return str(data)

        # struct like specifier
        return pack(field_format, data)

    def unpack(self, field_format, data, data_class_or_code=str, field=None):
        if self.debug:
            print "  unpack( %s | %r )" % (field_format, data)

        if field:
            address_field = self.find_address_field_for(field)
            if address_field is not None:
                if not self[address_field]:
                    return

        # void specifier
        if field_format[:1] == '_':
            if data_class_or_code != str:
                fields = {'self': self, 'inputDataLeft': data}
                fields.update(self.fields)
                return eval(data_class_or_code, {}, fields)
            else:
                return None

        # quote specifier
        if field_format[:1] == "'" or field_format[:1] == '"':
            answer = field_format[1:]
            if answer != data:
                raise Exception("Unpacked data doesn't match constant value '%r' should be '%r'" % (data, answer))
            return answer

        # address specifier
        two = field_format.split('&')
        if len(two) == 2:
            return self.unpack(two[0], data)

        # code specifier
        two = field_format.split('=')
        if len(two) >= 2:
            return self.unpack(two[0], data)

        # length specifier
        two = field_format.split('-')
        if len(two) == 2:
            return self.unpack(two[0], data)

        # array specifier
        two = field_format.split('*')
        if len(two) == 2:
            answer = []
            count = 0
            if two[0].isdigit():
                number = int(two[0])
            elif two[0]:
                count += self.calc_unpack_size(two[0], data)
                number = self.unpack(two[0], data[:count])
            else:
                number = -1

            while number and count < len(data):
                further = count + self.calc_unpack_size(two[1], data[count:])
                answer.append(self.unpack(two[1], data[count:further], data_class_or_code))
                count -= 1
                count = further
            return answer

        # "printf" string specifier
        if field_format[:1] == '%':
            # format string like specifier
            return format % data

        # asciiz specifier
        if field_format == 'z':
            if data[-1] != '\x00':
                raise Exception, ("%s 'z' field is not NUL terminated: %r" % (field, data))
            return data[:-1] # remove trailing NUL

        # unicode specifier
        if field_format == 'u':
            if data[-2:] != '\x00\x00':
                raise Exception,("%s 'u' field is not NUL-NUL terminated: %r" % (field, data))
            return data[:-2] # remove trailing NUL

        # DCE-RPC/NDR string specifier
        if field_format == 'w':
            l = unpack('<L', data[:4])[0]
            return data[12:12+l*2]

        # literal specifier
        if field_format == ':':
            return data_class_or_code(data)

        # struct like specifier
        return unpack(field_format, data)[0]

    def calcPackSize(self, field_format, data, field = None):
#        # print "  calcPackSize  %s:%r" %  (format, data)
        if field:
            addressField = self.find_address_field_for(field)
            if addressField is not None:
                if not self[addressField]:
                    return 0

        # void specifier
        if field_format[:1] == '_':
            return 0

        # quote specifier
        if field_format[:1] == "'" or field_format[:1] == '"':
            return len(field_format)-1

        # address specifier
        two = field_format.split('&')
        if len(two) == 2:
            return self.calcPackSize(two[0], data)

        # code specifier
        two = field_format.split('=')
        if len(two) >= 2:
            return self.calcPackSize(two[0], data)

        # length specifier
        two = field_format.split('-')
        if len(two) == 2:
            return self.calcPackSize(two[0], data)

        # array specifier
        two = field_format.split('*')
        if len(two) == 2:
            answer = 0
            if two[0].isdigit():
                    if int(two[0]) != len(data):
                        raise Exception, "Array field has a constant size, and it doesn't match the actual value"
            elif two[0]:
                answer += self.calcPackSize(two[0], len(data))

            for each in data:
                answer += self.calcPackSize(two[1], each)
            return answer

        # "printf" string specifier
        if field_format[:1] == '%':
            # format string like specifier
            return len(field_format % data)

        # asciiz specifier
        if field_format[:1] == 'z':
            return len(data)+1

        # asciiz specifier
        if field_format[:1] == 'u':
            l = len(data)
            return l + (l & 1 and 3 or 2)

        # DCE-RPC/NDR string specifier
        if field_format[:1] == 'w':
            l = len(data)
            return 12 + l + l % 2

        # literal specifier
        if field_format[:1] == ':':
            return len(data)

        # struct like specifier
        return calcsize(field_format)

    def calc_unpack_size(self, field_format, data, field=None):
        if self.debug:
            print "  calcUnpackSize( %s | %s | %r)" % (field, field_format, data)

        # void specifier
        if field_format[:1] == '_':
            return 0

        address_field = self.find_address_field_for(field)
        if address_field is not None:
            if not self[address_field]:
                return 0

        try:
            length_field = self.find_length_field_for(field)
            return self[length_field]
        except:
            pass

        # XXX: Try to match to actual values, raise if no match
        
        # quote specifier
        if field_format[:1] == "'" or field_format[:1] == '"':
            return len(field_format) - 1

        # address specifier
        two = field_format.split('&')
        if len(two) == 2:
            return self.calc_unpack_size(two[0], data)

        # code specifier
        two = field_format.split('=')
        if len(two) >= 2:
            return self.calc_unpack_size(two[0], data)

        # length specifier
        two = field_format.split('-')
        if len(two) == 2:
            return self.calc_unpack_size(two[0], data)

        # array specifier
        two = field_format.split('*')
        if len(two) == 2:
            answer = 0
            if two[0]:
                if two[0].isdigit():
                    number = int(two[0])
                else:
                    answer += self.calc_unpack_size(two[0], data)
                    number = self.unpack(two[0], data[:answer])

                while number:
                    number -= 1
                    answer += self.calc_unpack_size(two[1], data[answer:])
            else:
                while answer < len(data):
                    answer += self.calc_unpack_size(two[1], data[answer:])
            return answer

        # "printf" string specifier
        if field_format[:1] == '%':
            raise Exception("Can't guess the size of a printf like specifier for unpacking")

        # asciiz specifier
        if field_format[:1] == 'z':
            return data.index('\x00') + 1

        # asciiz specifier
        if field_format[:1] == 'u':
            l = data.index('\x00\x00')
            return l + (l & 1 and 3 or 2)

        # DCE-RPC/NDR string specifier
        if field_format[:1] == 'w':
            l = unpack('<L', data[:4])[0]
            return 12 + l * 2

        # literal specifier
        if field_format[:1] == ':':
            return len(data)

        # struct like specifier
        return calcsize(field_format)

    def calc_pack_field_size(self, field_name, field_format=None):
        if field_format is None:
            field_format = self.format_for_field(field_name)

        return self.calcPackSize(field_format, self[field_name])

    def format_for_field(self, field_name):
        for field in self.common_header + self.structure:
            if field[0] == field_name:
                return field[1]
        raise Exception("Field %s not found" % field_name)

    def find_address_field_for(self, field_name):
        descriptor = '&%s' % field_name
        l = len(descriptor)
        for field in self.common_header + self.structure:
            if field[1][-l:] == descriptor:
                return field[0]
        return None
        
    def find_length_field_for(self, field_name):
        descriptor = '-%s' % field_name
        l = len(descriptor)
        for field in self.common_header + self.structure:
            if field[1][-l:] == descriptor:
                return field[0]
        return None
        
    def zero_value(self, field_format):
        two = field_format.split('*')
        if len(two) == 2:
            if two[0].isdigit():
                return (self.zero_value(two[1]),) * int(two[0])
                        
        if not field_format.find('*') == -1:
            return ()
        if 's' in field_format:
            return ''
        if field_format in ['z', ':', 'u']:
            return ''
        if field_format == 'w':
            return '\x00\x00'

        return 0

    def clear(self):
        for field in self.common_header + self.structure:
            self[field[0]] = self.zero_value(field[1])

    def dump(self, message=None, indent=0):
        if message is None:
            message = self.__class__.__name__

        ind = ' ' * indent
        print "\n%s" % message

        fixed_fields = []
        for field in self.common_header + self.structure:
            i = field[0] 
            if i in self.fields:
                fixed_fields.append(i)
                if isinstance(self[i], Structure):
                    self[i].dump('%s%s:{' % (ind, i), indent=indent + 4)
                    print "%s}" % ind
                else:
                    print "%s%s: {%r}" % (ind, i, self[i])
        # Do we have remaining fields not defined in the structures? let's 
        # print them
        remaining_fields = list(set(self.fields) - set(fixed_fields))
        for i in remaining_fields:
            if isinstance(self[i], Structure):
                self[i].dump('%s%s:{' % (ind, i), indent=indent + 4)
                print "%s}" % ind
            else:
                print "%s%s: {%r}" % (ind, i, self[i])


class _StructureTest:
    alignment = 0
    def create(self,data = None):
        if data is not None:
            return self.theClass(data, alignment = self.alignment)
        else:
            return self.theClass(alignment = self.alignment)

    def run(self):
        print
        print "-"*70
        testName = self.__class__.__name__
        print "starting test: %s....." % testName
        a = self.create()
        self.populate(a)
        a.dump("packing.....")
        a_str = str(a)
        print "packed: %r" % a_str
        print "unpacking....."
        b = self.create(a_str)
        b.dump("unpacked.....")
        print "repacking....."
        b_str = str(b)
        if b_str != a_str:
            print "ERROR: original packed and repacked don't match"
            print "packed: %r" % b_str

class _Test_simple(_StructureTest):
    class theClass(Structure):
        commonHdr = ()
        structure = (
                ('int1', '!L'),
                ('len1','!L-z1'),
                ('arr1','B*<L'),
                ('z1', 'z'),
                ('u1','u'),
                ('', '"COCA'),
                ('len2','!H-:1'),
                ('', '"COCA'),
                (':1', ':'),
                ('int3','>L'),
                ('code1','>L=len(arr1)*2+0x1000'),
                )

    def populate(self, a):
        a['default'] = 'hola'
        a['int1'] = 0x3131
        a['int3'] = 0x45444342
        a['z1']   = 'hola'
        a['u1']   = 'hola'.encode('utf_16_le')
        a[':1']   = ':1234:'
        a['arr1'] = (0x12341234,0x88990077,0x41414141)
        # a['len1'] = 0x42424242

class _Test_fixedLength(_Test_simple):
    def populate(self, a):
        _Test_simple.populate(self, a)
        a['len1'] = 0x42424242

class _Test_simple_aligned4(_Test_simple):
    alignment = 4

class _Test_nested(_StructureTest):
    class theClass(Structure):
        class _Inner(Structure):
            structure = (('data', 'z'),)

        structure = (
            ('nest1', ':', _Inner),
            ('nest2', ':', _Inner),
            ('int', '<L'),
        )

    def populate(self, a):
        a['nest1'] = _Test_nested.theClass._Inner()
        a['nest2'] = _Test_nested.theClass._Inner()
        a['nest1']['data'] = 'hola manola'
        a['nest2']['data'] = 'chau loco'
        a['int'] = 0x12345678
    
class _Test_Optional(_StructureTest):
    class theClass(Structure):
        structure = (
                ('pName','<L&Name'),
                ('pList','<L&List'),
                ('Name','w'),
                ('List','<H*<L'),
            )
            
    def populate(self, a):
        a['Name'] = 'Optional test'
        a['List'] = (1,2,3,4)
        
class _Test_Optional_sparse(_Test_Optional):
    def populate(self, a):
        _Test_Optional.populate(self, a)
        del a['Name']

class _Test_AsciiZArray(_StructureTest):
    class theClass(Structure):
        structure = (
            ('head','<L'),
            ('array','B*z'),
            ('tail','<L'),
        )

    def populate(self, a):
        a['head'] = 0x1234
        a['tail'] = 0xabcd
        a['array'] = ('hola','manola','te traje')
        
class _Test_UnpackCode(_StructureTest):
    class theClass(Structure):
        structure = (
            ('leni','<L=len(uno)*2'),
            ('cuchi','_-uno','leni/2'),
            ('uno',':'),
            ('dos',':'),
        )

    def populate(self, a):
        a['uno'] = 'soy un loco!'
        a['dos'] = 'que haces fiera'

class _Test_AAA(_StructureTest):
    class theClass(Structure):
        commonHdr = ()
        structure = (
          ('iv', '!L=((init_vector & 0xFFFFFF) << 8) | ((pad & 0x3f) << 2) | (keyid & 3)'),
          ('init_vector',   '_','(iv >> 8)'),
          ('pad',           '_','((iv >>2) & 0x3F)'),
          ('keyid',         '_','( iv & 0x03 )'),
          ('dataLen',       '_-data', 'len(inputDataLeft)-4'),
          ('data',':'),
          ('icv','>L'),
        )

    def populate(self, a):
        a['init_vector']=0x01020304
        #a['pad']=int('01010101',2)
        a['pad']=int('010101',2)
        a['keyid']=0x07
        a['data']="\xA0\xA1\xA2\xA3\xA4\xA5\xA6\xA7\xA8\xA9"
        a['icv'] = 0x05060708
        #a['iv'] = 0x01020304
        
if __name__ == '__main__':
    _Test_simple().run()

    try:
        _Test_fixedLength().run()
    except:
        print "cannot repack because length is bogus"

    _Test_simple_aligned4().run()
    _Test_nested().run()
    _Test_Optional().run()
    _Test_Optional_sparse().run()
    _Test_AsciiZArray().run()
    _Test_UnpackCode().run()
    _Test_AAA().run()
