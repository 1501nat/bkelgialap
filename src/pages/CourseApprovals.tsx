import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { supabase } from '@/integrations/supabase/client';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { toast } from 'sonner';
import { CheckCircle, XCircle, Clock, BookOpen } from 'lucide-react';

interface CourseApproval {
  id: string;
  code: string;
  name: string;
  description: string | null;
  semester: string;
  year: number;
  status: string;
  lecturer_id: string;
  lecturer_name?: string;
  created_at: string;
}

const CourseApprovals = () => {
  const [courses, setCourses] = useState<CourseApproval[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchPendingCourses();
  }, []);

  const fetchPendingCourses = async () => {
    try {
      const { data: coursesData, error } = await supabase
        .from('courses')
        .select('*')
        .order('created_at', { ascending: false });

      if (error) throw error;

      const coursesWithLecturer = await Promise.all(
        (coursesData || []).map(async (course) => {
          const { data: profileData } = await supabase
            .from('profiles')
            .select('full_name')
            .eq('id', course.lecturer_id)
            .maybeSingle();
          
          return { ...course, lecturer_name: profileData?.full_name || 'Chưa xác định' };
        })
      );

      setCourses(coursesWithLecturer);
    } catch (error: any) {
      toast.error('Lỗi khi tải danh sách khóa học');
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const handleApproval = async (courseId: string, newStatus: 'approved' | 'rejected') => {
    try {
      const { error } = await supabase
        .from('courses')
        .update({ status: newStatus })
        .eq('id', courseId);

      if (error) throw error;

      toast.success(`Đã ${newStatus === 'approved' ? 'phê duyệt' : 'từ chối'} khóa học`);
      fetchPendingCourses();
    } catch (error: any) {
      toast.error('Lỗi khi xử lý yêu cầu');
      console.error(error);
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'pending':
        return <Badge variant="outline" className="bg-warning/10"><Clock className="h-3 w-3 mr-1" />Chờ duyệt</Badge>;
      case 'approved':
        return <Badge variant="outline" className="bg-success/10 text-success"><CheckCircle className="h-3 w-3 mr-1" />Đã duyệt</Badge>;
      case 'rejected':
        return <Badge variant="outline" className="bg-destructive/10 text-destructive"><XCircle className="h-3 w-3 mr-1" />Từ chối</Badge>;
      default:
        return null;
    }
  };

  if (loading) {
    return (
      <div className="container py-8 px-4">
        <div className="flex items-center justify-center h-64">
          <p className="text-muted-foreground">Đang tải...</p>
        </div>
      </div>
    );
  }

  const pendingCourses = courses.filter(c => c.status === 'pending');
  const approvedCourses = courses.filter(c => c.status === 'approved');
  const rejectedCourses = courses.filter(c => c.status === 'rejected');

  return (
    <div className="container py-8 px-4">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="mb-8"
      >
        <h1 className="text-3xl font-bold text-foreground mb-2">Phê duyệt Khóa học</h1>
        <p className="text-muted-foreground">
          {pendingCourses.length} khóa học chờ phê duyệt
        </p>
      </motion.div>

      {/* Pending Courses */}
      {pendingCourses.length > 0 && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.1 }}
          className="mb-8"
        >
          <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
            <Clock className="h-5 w-5 text-warning" />
            Chờ phê duyệt ({pendingCourses.length})
          </h2>
          <div className="grid gap-4">
            {pendingCourses.map((course, index) => (
              <motion.div
                key={course.id}
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: index * 0.05 }}
              >
                <Card className="shadow-card">
                  <CardContent className="p-6">
                    <div className="flex justify-between items-start gap-4">
                      <div className="flex-1">
                        <div className="flex items-center gap-3 mb-2">
                          <BookOpen className="h-5 w-5 text-primary" />
                          <h3 className="font-semibold text-lg">{course.code} - {course.name}</h3>
                          {getStatusBadge(course.status)}
                        </div>
                        <p className="text-sm text-muted-foreground mb-3">
                          {course.description || 'Chưa có mô tả'}
                        </p>
                        <div className="flex gap-4 text-sm text-muted-foreground">
                          <span>Giảng viên: <strong>{course.lecturer_name}</strong></span>
                          <span>Học kỳ: <strong>{course.semester} - {course.year}</strong></span>
                          <span>Ngày tạo: <strong>{new Date(course.created_at).toLocaleDateString('vi-VN')}</strong></span>
                        </div>
                      </div>
                      <div className="flex gap-2">
                        <Button
                          size="sm"
                          variant="outline"
                          className="bg-success/10 hover:bg-success/20"
                          onClick={() => handleApproval(course.id, 'approved')}
                        >
                          <CheckCircle className="h-4 w-4 mr-1" />
                          Phê duyệt
                        </Button>
                        <Button
                          size="sm"
                          variant="outline"
                          className="bg-destructive/10 hover:bg-destructive/20"
                          onClick={() => handleApproval(course.id, 'rejected')}
                        >
                          <XCircle className="h-4 w-4 mr-1" />
                          Từ chối
                        </Button>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </motion.div>
            ))}
          </div>
        </motion.div>
      )}

      {/* Approved Courses */}
      {approvedCourses.length > 0 && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.2 }}
          className="mb-8"
        >
          <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
            <CheckCircle className="h-5 w-5 text-success" />
            Đã phê duyệt ({approvedCourses.length})
          </h2>
          <div className="grid gap-4">
            {approvedCourses.map((course) => (
              <Card key={course.id} className="shadow-card">
                <CardContent className="p-4">
                  <div className="flex justify-between items-center">
                    <div>
                      <div className="flex items-center gap-2 mb-1">
                        <h3 className="font-medium">{course.code} - {course.name}</h3>
                        {getStatusBadge(course.status)}
                      </div>
                      <p className="text-sm text-muted-foreground">
                        {course.lecturer_name} • {course.semester} - {course.year}
                      </p>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </motion.div>
      )}

      {/* Rejected Courses */}
      {rejectedCourses.length > 0 && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.3 }}
        >
          <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
            <XCircle className="h-5 w-5 text-destructive" />
            Đã từ chối ({rejectedCourses.length})
          </h2>
          <div className="grid gap-4">
            {rejectedCourses.map((course) => (
              <Card key={course.id} className="shadow-card">
                <CardContent className="p-4">
                  <div className="flex justify-between items-center">
                    <div>
                      <div className="flex items-center gap-2 mb-1">
                        <h3 className="font-medium">{course.code} - {course.name}</h3>
                        {getStatusBadge(course.status)}
                      </div>
                      <p className="text-sm text-muted-foreground">
                        {course.lecturer_name} • {course.semester} - {course.year}
                      </p>
                    </div>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => handleApproval(course.id, 'approved')}
                    >
                      Phê duyệt lại
                    </Button>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </motion.div>
      )}

      {courses.length === 0 && (
        <div className="text-center py-12">
          <BookOpen className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
          <p className="text-muted-foreground">Chưa có khóa học nào</p>
        </div>
      )}
    </div>
  );
};

export default CourseApprovals;
