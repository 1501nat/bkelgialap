import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { useAuth } from '@/contexts/AuthContext';
import { supabase } from '@/integrations/supabase/client';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { toast } from 'sonner';
import { BookOpen, PlusCircle, Users, Calendar, Trash2, Edit, Plus, X } from 'lucide-react';
import { Link } from 'react-router-dom';

interface Course {
  id: string;
  code: string;
  name: string;
  description: string | null;
  semester: string;
  year: number;
  lecturer_id: string | null;
  color: string | null;
  created_at: string;
  status?: string;
  lecturer_name?: string;
  schedule?: { day: string; period: string }[];
}

const Courses = () => {
  const { role, user } = useAuth();
  const [courses, setCourses] = useState<Course[]>([]);
  const [studentEnrollments, setStudentEnrollments] = useState<Record<string, { status: string }>>({});
  const [loading, setLoading] = useState(true);
  const [open, setOpen] = useState(false);
  const [editingCourse, setEditingCourse] = useState<Course | null>(null);
  const [formData, setFormData] = useState({
    code: '',
    name: '',
    description: '',
    semester: '',
    year: new Date().getFullYear(),
    color: '#4CAF50',
    schedule: [] as { day: string; period: string }[],
  });
  const dayOptions = ['Thứ 2', 'Thứ 3', 'Thứ 4', 'Thứ 5', 'Thứ 6', 'Thứ 7', 'Chủ nhật'];

  useEffect(() => {
    fetchCourses();
  }, [role, user]);

  const fetchCourses = async () => {
    try {
      let query = supabase
        .from('courses')
        .select('*')
        .eq('status', 'approved'); // Tất cả vai trò chỉ thấy khóa học đã duyệt

      const { data: coursesData, error } = await query.order('created_at', { ascending: false });

      if (error) throw error;

      if (role === 'student' && user?.id) {
        const { data: enrollmentData } = await supabase
          .from('enrollments')
          .select('course_id, status')
          .eq('student_id', user.id);
        const map: Record<string, { status: string }> = {};
        (enrollmentData || []).forEach((enrollment: any) => {
          map[enrollment.course_id] = { status: enrollment.status };
        });
        setStudentEnrollments(map);
      } else {
        setStudentEnrollments({});
      }

      // Fetch lecturer names separately
      const coursesWithLecturer = await Promise.all(
        (coursesData || []).map(async (course) => {
          let lecturer_name: string | undefined;
          if (course.lecturer_id) {
            const { data: profileData } = await supabase
              .from('profiles')
              .select('full_name')
              .eq('id', course.lecturer_id)
              .single();
            lecturer_name = profileData?.full_name;
          }
          return {
            ...course,
            lecturer_name,
            schedule: (course.schedule as { day: string; period: string }[]) || [],
          };
        })
      );

      setCourses(coursesWithLecturer as Course[]);
    } catch (error: any) {
      toast.error('Lỗi khi tải danh sách khóa học');
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    try {
      const payload = {
        code: formData.code,
        name: formData.name,
        description: formData.description,
        semester: formData.semester,
        year: formData.year,
        color: formData.color,
        schedule: formData.schedule,
      };

      if (editingCourse) {
        const { error } = await supabase
          .from('courses')
          .update(payload)
          .eq('id', editingCourse.id);

        if (error) throw error;
        toast.success('Cập nhật khóa học thành công');
      } else {
        const status = role === 'lecturer' ? 'pending' : 'approved';
        const insertPayload = {
          ...payload,
          lecturer_id: role === 'lecturer' ? user?.id : null,
          status,
        };
        const { error } = await supabase
          .from('courses')
          .insert([insertPayload]);

        if (error) throw error;
        toast.success('Tạo khóa học thành công');
      }

      setOpen(false);
      setEditingCourse(null);
      setFormData({
        code: '',
        name: '',
        description: '',
        semester: '',
        year: new Date().getFullYear(),
        color: '#4CAF50',
        schedule: [],
      });
      fetchCourses();
    } catch (error: any) {
      toast.error(error.message || 'Có lỗi xảy ra');
    }
  };

  const handleDelete = async (id: string) => {
    if (!confirm('Bạn có chắc muốn xóa khóa học này?')) return;

    try {
      const { error } = await supabase
        .from('courses')
        .delete()
        .eq('id', id);

      if (error) throw error;
      toast.success('Đã xóa khóa học');
      fetchCourses();
    } catch (error: any) {
      toast.error('Lỗi khi xóa khóa học');
    }
  };

  const handleRegister = async (courseId: string) => {
    if (!user?.id) return;

    try {
      const enrollment = studentEnrollments[courseId];
      if (enrollment) {
        toast.error('Bạn đã đăng ký khóa học này rồi');
        return;
      }

      const { error } = await supabase
        .from('enrollments')
        .insert([{
          course_id: courseId,
          student_id: user.id,
          progress: 0,
          status: 'pending',
        }]);

      if (error) throw error;
      toast.success('Đăng ký thành công! Vui lòng chờ giảng viên duyệt.');
      fetchCourses();
    } catch (error: any) {
      toast.error(error.message || 'Không thể đăng ký khóa học');
    }
  };

  const openEditDialog = (course: Course) => {
    setEditingCourse(course);
    setFormData({
      code: course.code,
      name: course.name,
      description: course.description || '',
      semester: course.semester,
      year: course.year,
      color: course.color || '#4CAF50',
      schedule: course.schedule || [],
    });
    setOpen(true);
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

  return (
    <div className="container py-8 px-4">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="mb-8 flex justify-between items-center"
      >
        <div>
          <h1 className="text-3xl font-bold text-foreground mb-2">Khóa học</h1>
          <p className="text-muted-foreground">
            {role === 'admin'
              ? 'Quản lý tất cả khóa học'
              : role === 'lecturer'
                ? 'Khóa học bạn đang giảng dạy'
                : 'Đăng kí khóa học'}
          </p>
        </div>

        {(role === 'admin' || role === 'lecturer') && (
          <Dialog open={open} onOpenChange={setOpen}>
            <DialogTrigger asChild>
              <Button onClick={() => {
                setEditingCourse(null);
                setFormData({
                  code: '',
                  name: '',
                  description: '',
                  semester: '',
                  year: new Date().getFullYear(),
                  color: '#4CAF50',
                  schedule: [],
                });
              }}>
                <PlusCircle className="mr-2 h-4 w-4" />
                Tạo khóa học mới
              </Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>{editingCourse ? 'Chỉnh sửa khóa học' : 'Tạo khóa học mới'}</DialogTitle>
              </DialogHeader>
              <form onSubmit={handleSubmit} className="space-y-4">
                <div>
                  <Label htmlFor="code">Mã khóa học</Label>
                  <Input
                    id="code"
                    value={formData.code}
                    onChange={(e) => setFormData({ ...formData, code: e.target.value })}
                    placeholder="VD: CO3001"
                    required
                  />
                </div>
                <div>
                  <Label htmlFor="name">Tên khóa học</Label>
                  <Input
                    id="name"
                    value={formData.name}
                    onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                    placeholder="VD: Cong nghe Phan mem"
                    required
                  />
                </div>
                <div>
                  <Label htmlFor="description">Mô tả</Label>
                  <Textarea
                    id="description"
                    value={formData.description}
                    onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                    placeholder="Mo ta ve khoa hoc..."
                  />
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <Label htmlFor="semester">Học kỳ</Label>
                    <Input
                      id="semester"
                      value={formData.semester}
                      onChange={(e) => setFormData({ ...formData, semester: e.target.value })}
                      placeholder="VD: HK1"
                      required
                    />
                  </div>
                  <div>
                    <Label htmlFor="year">Năm</Label>
                    <Input
                      id="year"
                      type="number"
                      value={formData.year}
                      onChange={(e) => setFormData({ ...formData, year: parseInt(e.target.value) })}
                      required
                    />
                  </div>
                </div>
                <div>
                  <Label htmlFor="color">Màu sắc</Label>
                  <Input
                    id="color"
                    type="color"
                    value={formData.color}
                    onChange={(e) => setFormData({ ...formData, color: e.target.value })}
                  />
                </div>
                <div className="col-span-2">
                  <Label>Thời khóa biểu</Label>
                  <div className="space-y-2">
                    {formData.schedule.map((item, idx) => (
                      <div key={idx} className="flex items-center gap-2">
                        <select
                          value={item.day}
                          onChange={(e) => {
                            const next = [...formData.schedule];
                            next[idx] = { ...next[idx], day: e.target.value };
                            setFormData({ ...formData, schedule: next });
                          }}
                          className="border rounded-md px-3 py-2 text-sm"
                          required
                        >
                          <option value="">Chọn ngày</option>
                          {dayOptions.map((d) => (
                            <option key={d} value={d}>{d}</option>
                          ))}
                        </select>
                        <Input
                          placeholder="Tiết / Giờ học"
                          value={item.period}
                          onChange={(e) => {
                            const next = [...formData.schedule];
                            next[idx] = { ...next[idx], period: e.target.value };
                            setFormData({ ...formData, schedule: next });
                          }}
                          className="flex-1"
                          required
                        />
                        <Button
                          type="button"
                          variant="ghost"
                          size="icon"
                          onClick={() => {
                            const next = formData.schedule.filter((_, i) => i !== idx);
                            setFormData({ ...formData, schedule: next });
                          }}
                        >
                          <X className="h-4 w-4 text-destructive" />
                        </Button>
                      </div>
                    ))}
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      onClick={() =>
                        setFormData({
                          ...formData,
                          schedule: [...formData.schedule, { day: '', period: '' }],
                        })
                      }
                    >
                      <Plus className="h-4 w-4 mr-2" />
                      Thêm ngày/tiết
                    </Button>
                  </div>
                </div>
                <Button type="submit" className="w-full">
                  {editingCourse ? 'Cập nhật' : 'Tạo khóa học'}
                </Button>
              </form>
            </DialogContent>
          </Dialog>
        )}
      </motion.div>

      {role === 'student' ? (
        <>
          {/* Danh sách khóa học đã đăng ký */}
          <div className="mb-8">
            <h2 className="text-xl font-semibold mb-4">Khóa học đã đăng ký</h2>
            {courses.filter(c => studentEnrollments[c.id]).length > 0 ? (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {courses
                  .filter(course => studentEnrollments[course.id])
                  .map((course, index) => {
                    const enrollmentStatus = studentEnrollments[course.id]?.status;
                    return (
                      <motion.div
                        key={course.id}
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: index * 0.1 }}
                      >
                        <Card className="shadow-card hover:shadow-hover transition-all cursor-pointer h-full">
                          <CardHeader className="pb-4" style={{ borderLeft: `4px solid ${course.color}` }}>
                            <div className="flex-1">
                              <CardTitle className="text-lg mb-1">{course.code}</CardTitle>
                              <CardDescription className="text-base font-medium text-foreground">
                                {course.name}
                              </CardDescription>
                            </div>
                          </CardHeader>
                          <CardContent className="space-y-3">
                            <div className={`text-xs font-medium px-2 py-1 rounded-full inline-flex ${
                              enrollmentStatus === 'approved' 
                                ? 'bg-green-100 text-green-700' 
                                : enrollmentStatus === 'pending'
                                  ? 'bg-yellow-100 text-yellow-700'
                                  : 'bg-red-100 text-red-700'
                            }`}>
                              {enrollmentStatus === 'approved' ? 'Đã được duyệt' : enrollmentStatus === 'pending' ? 'Chờ duyệt' : 'Bị từ chối'}
                            </div>
                            <div className="flex gap-2 mt-4">
                              <Link to={`/courses/${course.id}`} className="flex-1">
                                <Button variant="outline" className="w-full">
                                  <BookOpen className="mr-2 h-4 w-4" />
                                  Xem chi tiết
                                </Button>
                              </Link>
                            </div>
                          </CardContent>
                        </Card>
                      </motion.div>
                    );
                  })}
              </div>
            ) : (
              <p className="text-muted-foreground">Bạn chưa đăng ký khóa học nào.</p>
            )}
          </div>

          {/* Danh sách khóa học chưa đăng ký */}
          <div>
            <h2 className="text-xl font-semibold mb-4">Khóa học khác</h2>
            {courses.filter(c => !studentEnrollments[c.id]).length > 0 ? (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {courses
                  .filter(course => !studentEnrollments[course.id])
                  .map((course, index) => (
                    <motion.div
                      key={course.id}
                      initial={{ opacity: 0, y: 20 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: index * 0.1 }}
                    >
                      <Card className="shadow-card hover:shadow-hover transition-all cursor-pointer h-full">
                        <CardHeader className="pb-4" style={{ borderLeft: `4px solid ${course.color}` }}>
                          <div className="flex-1">
                            <CardTitle className="text-lg mb-1">{course.code}</CardTitle>
                            <CardDescription className="text-base font-medium text-foreground">
                              {course.name}
                            </CardDescription>
                          </div>
                        </CardHeader>
                        <CardContent className="space-y-3">
                          <div className="flex gap-2 mt-4">
                            <Link to={`/courses/${course.id}`} className="flex-1">
                              <Button variant="outline" className="w-full">
                                <BookOpen className="mr-2 h-4 w-4" />
                                Xem chi tiết
                              </Button>
                            </Link>
                            <Button
                              className="flex-1"
                              onClick={() => handleRegister(course.id)}
                            >
                              Đăng ký
                            </Button>
                          </div>
                        </CardContent>
                      </Card>
                    </motion.div>
                  ))}
              </div>
            ) : (
              <p className="text-muted-foreground">Không có khóa học nào khác.</p>
            )}
          </div>
        </>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {courses.map((course, index) => (
            <motion.div
              key={course.id}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.1 }}
            >
              <Card className="shadow-card hover:shadow-hover transition-all cursor-pointer h-full">
                <CardHeader className="pb-4" style={{ borderLeft: `4px solid ${course.color}` }}>
                  <div className="flex justify-between items-start">
                    <div className="flex-1">
                      <CardTitle className="text-lg mb-1">{course.code}</CardTitle>
                      <CardDescription className="text-base font-medium text-foreground">
                        {course.name}
                      </CardDescription>
                    </div>
                    {(role === 'admin' || (role === 'lecturer' && course.lecturer_id === user?.id)) && (
                      <div className="flex gap-2">
                        <Button
                          size="icon"
                          variant="ghost"
                          onClick={() => openEditDialog(course)}
                        >
                          <Edit className="h-4 w-4" />
                        </Button>
                        <Button
                          size="icon"
                          variant="ghost"
                          onClick={() => handleDelete(course.id)}
                        >
                          <Trash2 className="h-4 w-4 text-destructive" />
                        </Button>
                      </div>
                    )}
                  </div>
                </CardHeader>
                <CardContent className="space-y-3">
                  <Link to={`/courses/${course.id}`}>
                    <Button variant="outline" className="w-full mt-2">
                      <BookOpen className="mr-2 h-4 w-4" />
                      Xem chi tiết
                    </Button>
                  </Link>
                </CardContent>
              </Card>
            </motion.div>
          ))}
        </div>
      )}

      {courses.length === 0 && role !== 'student' && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="text-center py-12"
        >
          <BookOpen className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
          <p className="text-muted-foreground">Chưa có khóa học nào</p>
        </motion.div>
      )}
    </div>
  );
};

export default Courses;


