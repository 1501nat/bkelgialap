import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { useAuth } from '@/contexts/AuthContext';
import { supabase } from '@/integrations/supabase/client';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { toast } from 'sonner';
import { Calendar as CalendarIcon, Users, CheckCircle, XCircle, Clock } from 'lucide-react';
import { format } from 'date-fns';
import { Calendar } from '@/components/ui/calendar';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';

interface AttendanceRecord {
  id: string;
  course_id: string;
  student_id: string;
  session_date: string;
  status: 'present' | 'absent' | 'late';
  created_at: string;
  course_name?: string;
  student_name?: string;
}

const Attendance = () => {
  const { role, user } = useAuth();
  const [records, setRecords] = useState<AttendanceRecord[]>([]);
  const [courses, setCourses] = useState<any[]>([]);
  const [students, setStudents] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [open, setOpen] = useState(false);
  const [selectedCourse, setSelectedCourse] = useState('');
  const [selectedDate, setSelectedDate] = useState<Date>(new Date());
  const [attendanceData, setAttendanceData] = useState<Record<string, string>>({});

  useEffect(() => {
    fetchData();
  }, [role, user]);

  const fetchData = async () => {
    try {
      // Fetch courses
      let coursesQuery = supabase.from('courses').select('*');
      
      if (role === 'lecturer') {
        coursesQuery = coursesQuery.eq('lecturer_id', user?.id);
      } else if (role === 'student') {
        const { data: enrollments } = await supabase
          .from('enrollments')
          .select('course_id')
          .eq('student_id', user?.id);
        const courseIds = enrollments?.map(e => e.course_id) || [];
        if (courseIds.length > 0) {
          coursesQuery = coursesQuery.in('id', courseIds);
        }
      }

      const { data: coursesData } = await coursesQuery;
      setCourses(coursesData || []);

      // Fetch attendance records
      let attendanceQuery = supabase
        .from('attendance')
        .select('*')
        .order('session_date', { ascending: false });

      if (role === 'student') {
        attendanceQuery = attendanceQuery.eq('student_id', user?.id);
      } else if (role === 'lecturer') {
        const courseIds = coursesData?.map(c => c.id) || [];
        if (courseIds.length > 0) {
          attendanceQuery = attendanceQuery.in('course_id', courseIds);
        }
      }

      const { data: attendanceData, error } = await attendanceQuery;
      if (error) throw error;

      // Add course and student names
      const recordsWithDetails = await Promise.all(
        (attendanceData || []).map(async (record) => {
          const course = coursesData?.find(c => c.id === record.course_id);
          
          const { data: profile } = await supabase
            .from('profiles')
            .select('full_name')
            .eq('id', record.student_id)
            .single();
          
          return {
            ...record,
            course_name: course?.name,
            student_name: profile?.full_name
          };
        })
      );

      setRecords(recordsWithDetails as AttendanceRecord[]);
    } catch (error: any) {
      toast.error('Lỗi khi tải danh sách điểm danh');
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const fetchStudentsForCourse = async (courseId: string) => {
    try {
      const { data: enrollments } = await supabase
        .from('enrollments')
        .select('student_id')
        .eq('course_id', courseId);

      const studentIds = enrollments?.map(e => e.student_id) || [];
      
      if (studentIds.length > 0) {
        const { data: profiles } = await supabase
          .from('profiles')
          .select('id, full_name, email')
          .in('id', studentIds);
        
        setStudents(profiles || []);
        
        // Initialize attendance data
        const initial: Record<string, string> = {};
        profiles?.forEach(student => {
          initial[student.id] = 'present';
        });
        setAttendanceData(initial);
      }
    } catch (error: any) {
      toast.error('Lỗi khi tải danh sách sinh viên');
      console.error(error);
    }
  };

  const handleCourseChange = (courseId: string) => {
    setSelectedCourse(courseId);
    fetchStudentsForCourse(courseId);
  };

  const handleSubmitAttendance = async () => {
    if (!selectedCourse) {
      toast.error('Vui lòng chọn khóa học');
      return;
    }

    try {
      const attendanceRecords = Object.entries(attendanceData).map(([studentId, status]) => ({
        course_id: selectedCourse,
        student_id: studentId,
        session_date: format(selectedDate, 'yyyy-MM-dd'),
        status: status as 'present' | 'absent' | 'late'
      }));

      const { error } = await supabase
        .from('attendance')
        .insert(attendanceRecords);

      if (error) throw error;
      
      toast.success('Điểm danh thành công');
      setOpen(false);
      fetchData();
    } catch (error: any) {
      toast.error(error.message || 'Có lỗi xảy ra');
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'present':
        return <CheckCircle className="h-5 w-5 text-success" />;
      case 'absent':
        return <XCircle className="h-5 w-5 text-destructive" />;
      case 'late':
        return <Clock className="h-5 w-5 text-warning" />;
      default:
        return null;
    }
  };

  const getStatusLabel = (status: string) => {
    switch (status) {
      case 'present': return 'Có mặt';
      case 'absent': return 'Vắng';
      case 'late': return 'Trễ';
      default: return status;
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
      </div>
    );
  }

  return (
    <div className="container py-8 px-4">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="mb-8"
      >
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-foreground mb-2">Điểm danh</h1>
            <p className="text-muted-foreground">
              {role === 'student' 
                ? 'Xem lịch sử điểm danh của bạn' 
                : 'Quản lý điểm danh cho các khóa học'}
            </p>
          </div>
          {(role === 'admin' || role === 'lecturer') && (
            <Dialog open={open} onOpenChange={setOpen}>
              <DialogTrigger asChild>
                <Button>
                  <Users className="h-4 w-4 mr-2" />
                  Điểm danh
                </Button>
              </DialogTrigger>
              <DialogContent className="max-w-3xl max-h-[80vh] overflow-y-auto">
                <DialogHeader>
                  <DialogTitle>Điểm danh sinh viên</DialogTitle>
                </DialogHeader>
                <div className="space-y-4">
                  <div>
                    <Label>Khóa học</Label>
                    <Select value={selectedCourse} onValueChange={handleCourseChange}>
                      <SelectTrigger>
                        <SelectValue placeholder="Chọn khóa học" />
                      </SelectTrigger>
                      <SelectContent>
                        {courses.map((course) => (
                          <SelectItem key={course.id} value={course.id}>
                            {course.code} - {course.name}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>

                  <div>
                    <Label>Ngày điểm danh</Label>
                    <Popover>
                      <PopoverTrigger asChild>
                        <Button variant="outline" className="w-full justify-start text-left">
                          <CalendarIcon className="mr-2 h-4 w-4" />
                          {format(selectedDate, 'dd/MM/yyyy')}
                        </Button>
                      </PopoverTrigger>
                      <PopoverContent className="w-auto p-0">
                        <Calendar
                          mode="single"
                          selected={selectedDate}
                          onSelect={(date) => date && setSelectedDate(date)}
                        />
                      </PopoverContent>
                    </Popover>
                  </div>

                  {selectedCourse && students.length > 0 && (
                    <div>
                      <Label className="mb-2 block">Danh sách sinh viên</Label>
                      <div className="space-y-2 max-h-96 overflow-y-auto">
                        {students.map((student) => (
                          <Card key={student.id}>
                            <CardContent className="flex items-center justify-between p-4">
                              <div>
                                <p className="font-medium">{student.full_name}</p>
                                <p className="text-sm text-muted-foreground">{student.email}</p>
                              </div>
                              <Select
                                value={attendanceData[student.id]}
                                onValueChange={(value) => 
                                  setAttendanceData({ ...attendanceData, [student.id]: value })
                                }
                              >
                                <SelectTrigger className="w-32">
                                  <SelectValue />
                                </SelectTrigger>
                                <SelectContent>
                                  <SelectItem value="present">Có mặt</SelectItem>
                                  <SelectItem value="absent">Vắng</SelectItem>
                                  <SelectItem value="late">Trễ</SelectItem>
                                </SelectContent>
                              </Select>
                            </CardContent>
                          </Card>
                        ))}
                      </div>
                    </div>
                  )}

                  <div className="flex justify-end gap-2">
                    <Button type="button" variant="outline" onClick={() => setOpen(false)}>
                      Hủy
                    </Button>
                    <Button onClick={handleSubmitAttendance} disabled={!selectedCourse || students.length === 0}>
                      Lưu điểm danh
                    </Button>
                  </div>
                </div>
              </DialogContent>
            </Dialog>
          )}
        </div>
      </motion.div>

      {records.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12">
            <CalendarIcon className="h-12 w-12 text-muted-foreground mb-4" />
            <p className="text-muted-foreground">Chưa có dữ liệu điểm danh</p>
          </CardContent>
        </Card>
      ) : (
        <div className="grid gap-4">
          {records.map((record, index) => (
            <motion.div
              key={record.id}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.05 }}
            >
              <Card className="shadow-card hover:shadow-hover transition-shadow">
                <CardContent className="flex items-center justify-between p-6">
                  <div className="flex items-center gap-4">
                    {getStatusIcon(record.status)}
                    <div>
                      <p className="font-medium text-foreground">
                        {role === 'student' ? record.course_name : record.student_name}
                      </p>
                      <div className="flex items-center gap-4 text-sm text-muted-foreground mt-1">
                        {role !== 'student' && (
                          <span className="text-primary">{record.course_name}</span>
                        )}
                        <span>{format(new Date(record.session_date), 'dd/MM/yyyy')}</span>
                      </div>
                    </div>
                  </div>
                  <div className="text-right">
                    <span className={`font-medium ${
                      record.status === 'present' ? 'text-success' :
                      record.status === 'absent' ? 'text-destructive' :
                      'text-warning'
                    }`}>
                      {getStatusLabel(record.status)}
                    </span>
                  </div>
                </CardContent>
              </Card>
            </motion.div>
          ))}
        </div>
      )}
    </div>
  );
};

export default Attendance;
