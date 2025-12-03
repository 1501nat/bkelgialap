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
import { UserPlus, Users, Trash2, BookOpen, Check, X, Clock } from 'lucide-react';
import { format } from 'date-fns';

interface Enrollment {
  id: string;
  course_id: string;
  student_id: string;
  progress: number;
  enrolled_at: string;
  status: string;
  course_name?: string;
  course_code?: string;
  student_name?: string;
  student_email?: string;
}

interface CourseGroup {
  course_id: string;
  course_name: string;
  course_code: string;
  pending: Enrollment[];
  approved: Enrollment[];
  rejected: Enrollment[];
}

const Enrollments = () => {
  const { role, user } = useAuth();
  const [courseGroups, setCourseGroups] = useState<CourseGroup[]>([]);
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
        } else {
          setCourseGroups([]);
          setLoading(false);
          return;
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

      // Group by course
      const groupMap = new Map<string, CourseGroup>();
      
      enrollmentsWithDetails.forEach((enrollment) => {
        if (!groupMap.has(enrollment.course_id)) {
          groupMap.set(enrollment.course_id, {
            course_id: enrollment.course_id,
            course_name: enrollment.course_name || '',
            course_code: enrollment.course_code || '',
            pending: [],
            approved: [],
            rejected: []
          });
        }
        
        const group = groupMap.get(enrollment.course_id)!;
        if (enrollment.status === 'pending') {
          group.pending.push(enrollment);
        } else if (enrollment.status === 'approved') {
          group.approved.push(enrollment);
        } else {
          group.rejected.push(enrollment);
        }
      });

      setCourseGroups(Array.from(groupMap.values()));
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
          progress: 0,
          status: 'approved'
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

  const handleApprove = async (id: string) => {
    try {
      const { error } = await supabase
        .from('enrollments')
        .update({ status: 'approved' })
        .eq('id', id);

      if (error) throw error;
      toast.success('Đã duyệt sinh viên');
      fetchData();
    } catch (error: any) {
      toast.error(error.message || 'Có lỗi xảy ra');
    }
  };

  const handleReject = async (id: string) => {
    try {
      const { error } = await supabase
        .from('enrollments')
        .update({ status: 'rejected' })
        .eq('id', id);

      if (error) throw error;
      toast.success('Đã từ chối sinh viên');
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

  const EnrollmentCard = ({ enrollment, showActions = true }: { enrollment: Enrollment; showActions?: boolean }) => (
    <div className="flex items-center justify-between p-3 bg-muted/50 rounded-lg">
      <div className="flex-1">
        <p className="font-medium text-sm">{enrollment.student_name}</p>
        <p className="text-xs text-muted-foreground">{enrollment.student_email}</p>
        <p className="text-xs text-muted-foreground">
          Đăng ký: {format(new Date(enrollment.enrolled_at), 'dd/MM/yyyy')}
        </p>
      </div>
      {showActions && (role === 'lecturer' || role === 'admin') && (
        <div className="flex items-center gap-1">
          {enrollment.status === 'pending' && (
            <>
              <Button size="icon" variant="ghost" onClick={() => handleApprove(enrollment.id)} title="Duyệt">
                <Check className="h-4 w-4 text-green-600" />
              </Button>
              <Button size="icon" variant="ghost" onClick={() => handleReject(enrollment.id)} title="Từ chối">
                <X className="h-4 w-4 text-red-600" />
              </Button>
            </>
          )}
          {enrollment.status === 'rejected' && (
            <Button size="icon" variant="ghost" onClick={() => handleApprove(enrollment.id)} title="Duyệt lại">
              <Check className="h-4 w-4 text-green-600" />
            </Button>
          )}
          <Button size="icon" variant="ghost" onClick={() => handleUnenroll(enrollment.id)} title="Xóa">
            <Trash2 className="h-4 w-4 text-destructive" />
          </Button>
        </div>
      )}
    </div>
  );

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

      {courseGroups.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12">
            <Users className="h-12 w-12 text-muted-foreground mb-4" />
            <p className="text-muted-foreground">Chưa có sinh viên nào đăng ký</p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-6">
          {courseGroups.map((group, index) => (
            <motion.div
              key={group.course_id}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.1 }}
            >
              <Card className="shadow-card">
                <CardHeader>
                  <div className="flex items-center gap-2">
                    <BookOpen className="h-5 w-5 text-primary" />
                    <CardTitle className="text-lg">
                      {group.course_code} - {group.course_name}
                    </CardTitle>
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    {/* Pending */}
                    <div className="space-y-2">
                      <div className="flex items-center gap-2 mb-3">
                        <Clock className="h-4 w-4 text-yellow-600" />
                        <h4 className="font-medium text-sm">Chờ duyệt ({group.pending.length})</h4>
                      </div>
                      {group.pending.length === 0 ? (
                        <p className="text-xs text-muted-foreground">Không có</p>
                      ) : (
                        <div className="space-y-2">
                          {group.pending.map((e) => (
                            <EnrollmentCard key={e.id} enrollment={e} />
                          ))}
                        </div>
                      )}
                    </div>

                    {/* Approved */}
                    <div className="space-y-2">
                      <div className="flex items-center gap-2 mb-3">
                        <Check className="h-4 w-4 text-green-600" />
                        <h4 className="font-medium text-sm">Đã duyệt ({group.approved.length})</h4>
                      </div>
                      {group.approved.length === 0 ? (
                        <p className="text-xs text-muted-foreground">Không có</p>
                      ) : (
                        <div className="space-y-2">
                          {group.approved.map((e) => (
                            <EnrollmentCard key={e.id} enrollment={e} showActions={false} />
                          ))}
                        </div>
                      )}
                    </div>

                    {/* Rejected */}
                    <div className="space-y-2">
                      <div className="flex items-center gap-2 mb-3">
                        <X className="h-4 w-4 text-red-600" />
                        <h4 className="font-medium text-sm">Đã từ chối ({group.rejected.length})</h4>
                      </div>
                      {group.rejected.length === 0 ? (
                        <p className="text-xs text-muted-foreground">Không có</p>
                      ) : (
                        <div className="space-y-2">
                          {group.rejected.map((e) => (
                            <EnrollmentCard key={e.id} enrollment={e} />
                          ))}
                        </div>
                      )}
                    </div>
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

export default Enrollments;