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
import { UserPlus, Users, Trash2, BookOpen } from 'lucide-react';
import { format } from 'date-fns';

interface Enrollment {
  id: string;
  course_id: string;
  student_id: string;
  progress: number;
  enrolled_at: string;
  course_name?: string;
  course_code?: string;
  student_name?: string;
  student_email?: string;
}

const Enrollments = () => {
  const { role, user } = useAuth();
  const [enrollments, setEnrollments] = useState<Enrollment[]>([]);
  const [courses, setCourses] = useState<any[]>([]);
  const [students, setStudents] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [open, setOpen] = useState(false);
  const [selectedCourse, setSelectedCourse] = useState('');
  const [selectedStudent, setSelectedStudent] = useState('');

  useEffect(() => {
    fetchData();
  }, [role, user]);

  const fetchData = async () => {
    try {
      // Fetch courses
      let coursesQuery = supabase.from('courses').select('*');
      
      if (role === 'lecturer') {
        coursesQuery = coursesQuery.eq('lecturer_id', user?.id);
      }

      const { data: coursesData } = await coursesQuery;
      setCourses(coursesData || []);

      // Fetch students (for admin)
      if (role === 'admin') {
        const { data: studentRoles } = await supabase
          .from('user_roles')
          .select('user_id')
          .eq('role', 'student');
        
        const studentIds = studentRoles?.map(r => r.user_id) || [];
        
        if (studentIds.length > 0) {
          const { data: profiles } = await supabase
            .from('profiles')
            .select('id, full_name, email')
            .in('id', studentIds);
          
          setStudents(profiles || []);
        }
      }

      // Fetch enrollments
      let enrollmentsQuery = supabase
        .from('enrollments')
        .select('*')
        .order('enrolled_at', { ascending: false });

      if (role === 'lecturer') {
        const courseIds = coursesData?.map(c => c.id) || [];
        if (courseIds.length > 0) {
          enrollmentsQuery = enrollmentsQuery.in('course_id', courseIds);
        }
      }

      const { data: enrollmentsData, error } = await enrollmentsQuery;
      if (error) throw error;

      // Add course and student details
      const enrollmentsWithDetails = await Promise.all(
        (enrollmentsData || []).map(async (enrollment) => {
          const course = coursesData?.find(c => c.id === enrollment.course_id);
          
          const { data: profile } = await supabase
            .from('profiles')
            .select('full_name, email')
            .eq('id', enrollment.student_id)
            .single();
          
          return {
            ...enrollment,
            course_name: course?.name,
            course_code: course?.code,
            student_name: profile?.full_name,
            student_email: profile?.email
          };
        })
      );

      setEnrollments(enrollmentsWithDetails);
    } catch (error: any) {
      toast.error('Lỗi khi tải danh sách ghi danh');
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const handleEnroll = async () => {
    if (!selectedCourse || !selectedStudent) {
      toast.error('Vui lòng chọn khóa học và sinh viên');
      return;
    }

    try {
      // Check if already enrolled
      const { data: existing } = await supabase
        .from('enrollments')
        .select('id')
        .eq('course_id', selectedCourse)
        .eq('student_id', selectedStudent)
        .maybeSingle();

      if (existing) {
        toast.error('Sinh viên đã được ghi danh vào khóa học này');
        return;
      }

      const { error } = await supabase
        .from('enrollments')
        .insert([{
          course_id: selectedCourse,
          student_id: selectedStudent,
          progress: 0
        }]);

      if (error) throw error;
      
      toast.success('Ghi danh thành công');
      setOpen(false);
      setSelectedCourse('');
      setSelectedStudent('');
      fetchData();
    } catch (error: any) {
      toast.error(error.message || 'Có lỗi xảy ra');
    }
  };


  const handleUnenroll = async (id: string) => {
    if (!confirm('Bạn có chắc chắn muốn hủy ghi danh này?')) return;
    
    try {
      const { error } = await supabase
        .from('enrollments')
        .delete()
        .eq('id', id);

      if (error) throw error;
      toast.success('Hủy ghi danh thành công');
      fetchData();
    } catch (error: any) {
      toast.error(error.message || 'Có lỗi xảy ra');
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
            <h1 className="text-3xl font-bold text-foreground mb-2">Ghi danh</h1>
            <p className="text-muted-foreground">
              Quản lý việc ghi danh sinh viên vào các khóa học
            </p>
          </div>
          {role === 'admin' && (
            <Dialog open={open} onOpenChange={setOpen}>
              <DialogTrigger asChild>
                <Button>
                  <UserPlus className="h-4 w-4 mr-2" />
                  Ghi danh sinh viên
                </Button>
              </DialogTrigger>
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>Ghi danh sinh viên vào khóa học</DialogTitle>
                </DialogHeader>
                <div className="space-y-4">
                  <div>
                    <Label>Khóa học</Label>
                    <Select value={selectedCourse} onValueChange={setSelectedCourse}>
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
                    <Label>Sinh viên</Label>
                    <Select value={selectedStudent} onValueChange={setSelectedStudent}>
                      <SelectTrigger>
                        <SelectValue placeholder="Chọn sinh viên" />
                      </SelectTrigger>
                      <SelectContent>
                        {students.map((student) => (
                          <SelectItem key={student.id} value={student.id}>
                            {student.full_name} ({student.email})
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>

                  <div className="flex justify-end gap-2">
                    <Button type="button" variant="outline" onClick={() => setOpen(false)}>
                      Hủy
                    </Button>
                    <Button onClick={handleEnroll}>
                      Ghi danh
                    </Button>
                  </div>
                </div>
              </DialogContent>
            </Dialog>
          )}
        </div>
      </motion.div>

      {enrollments.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12">
            <Users className="h-12 w-12 text-muted-foreground mb-4" />
            <p className="text-muted-foreground">Chưa có sinh viên nào được ghi danh</p>
          </CardContent>
        </Card>
      ) : (
        <div className="grid gap-4">
          {enrollments.map((enrollment, index) => (
            <motion.div
              key={enrollment.id}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.05 }}
            >
              <Card className="shadow-card hover:shadow-hover transition-shadow">
                <CardHeader>
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-2">
                        <BookOpen className="h-5 w-5 text-primary" />
                        <CardTitle className="text-lg">
                          {enrollment.course_code} - {enrollment.course_name}
                        </CardTitle>
                      </div>
                      <div className="space-y-1 text-sm text-muted-foreground">
                        <p className="font-medium text-foreground">
                          {enrollment.student_name}
                        </p>
                        <p>{enrollment.student_email}</p>
                        <p>Ghi danh: {format(new Date(enrollment.enrolled_at), 'dd/MM/yyyy')}</p>
                        <p>Tiến độ: {enrollment.progress}%</p>
                      </div>
                    </div>
                    <div className="flex flex-col items-end gap-2">
                      {(role === 'lecturer' || role === 'admin') && (
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={() => handleUnenroll(enrollment.id)}
                        >
                          <Trash2 className="h-4 w-4 text-destructive" />
                        </Button>
                      )}
                    </div>
                  </div>
                </CardHeader>

              </Card>
            </motion.div>
          ))}
        </div>
      )}
    </div>
  );
};

export default Enrollments;
