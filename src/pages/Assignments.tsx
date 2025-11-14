import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { useAuth } from '@/contexts/AuthContext';
import { supabase } from '@/integrations/supabase/client';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { toast } from 'sonner';
import { FileText, PlusCircle, Clock, CheckCircle, Calendar, Edit, Trash2 } from 'lucide-react';
import { format } from 'date-fns';

interface Assignment {
  id: string;
  title: string;
  description: string | null;
  course_id: string;
  due_date: string | null;
  max_score: number;
  created_at: string;
  course_name?: string;
  submission_status?: 'submitted' | 'graded' | 'pending';
  score?: number;
}

const Assignments = () => {
  const { role, user } = useAuth();
  const [assignments, setAssignments] = useState<Assignment[]>([]);
  const [courses, setCourses] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [open, setOpen] = useState(false);
  const [editingAssignment, setEditingAssignment] = useState<Assignment | null>(null);
  const [formData, setFormData] = useState({
    title: '',
    description: '',
    course_id: '',
    due_date: '',
    max_score: 100
  });

  useEffect(() => {
    fetchData();
  }, [role, user]);

  const fetchData = async () => {
    try {
      // Fetch courses first
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

      // Fetch assignments
      let assignmentsQuery = supabase
        .from('assignments')
        .select('*')
        .order('due_date', { ascending: true });

      if (role === 'student') {
        const courseIds = coursesData?.map(c => c.id) || [];
        if (courseIds.length > 0) {
          assignmentsQuery = assignmentsQuery.in('course_id', courseIds);
        }
      } else if (role === 'lecturer') {
        const courseIds = coursesData?.map(c => c.id) || [];
        if (courseIds.length > 0) {
          assignmentsQuery = assignmentsQuery.in('course_id', courseIds);
        }
      }

      const { data: assignmentsData, error } = await assignmentsQuery;
      if (error) throw error;

      // Add course names and submission status
      const assignmentsWithDetails = await Promise.all(
        (assignmentsData || []).map(async (assignment) => {
          const course = coursesData?.find(c => c.id === assignment.course_id);
          
          let submissionStatus = 'pending';
          let score = undefined;
          
          if (role === 'student') {
            const { data: submission } = await supabase
              .from('submissions')
              .select('score, graded_at')
              .eq('assignment_id', assignment.id)
              .eq('student_id', user?.id)
              .maybeSingle();
            
            if (submission) {
              submissionStatus = submission.graded_at ? 'graded' : 'submitted';
              score = submission.score;
            }
          }
          
          return {
            ...assignment,
            course_name: course?.name,
            submission_status: submissionStatus as any,
            score
          };
        })
      );

      setAssignments(assignmentsWithDetails);
    } catch (error: any) {
      toast.error('Lỗi khi tải danh sách bài tập');
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    try {
      if (editingAssignment) {
        const { error } = await supabase
          .from('assignments')
          .update(formData)
          .eq('id', editingAssignment.id);

        if (error) throw error;
        toast.success('Cập nhật bài tập thành công');
      } else {
        const { error } = await supabase
          .from('assignments')
          .insert([formData]);

        if (error) throw error;
        toast.success('Tạo bài tập thành công');
      }

      setOpen(false);
      setEditingAssignment(null);
      resetForm();
      fetchData();
    } catch (error: any) {
      toast.error(error.message || 'Có lỗi xảy ra');
    }
  };

  const handleDelete = async (id: string) => {
    if (!confirm('Bạn có chắc chắn muốn xóa bài tập này?')) return;
    
    try {
      const { error } = await supabase
        .from('assignments')
        .delete()
        .eq('id', id);

      if (error) throw error;
      toast.success('Xóa bài tập thành công');
      fetchData();
    } catch (error: any) {
      toast.error(error.message || 'Có lỗi xảy ra');
    }
  };

  const resetForm = () => {
    setFormData({
      title: '',
      description: '',
      course_id: '',
      due_date: '',
      max_score: 100
    });
  };

  const openEditDialog = (assignment: Assignment) => {
    setEditingAssignment(assignment);
    setFormData({
      title: assignment.title,
      description: assignment.description || '',
      course_id: assignment.course_id,
      due_date: assignment.due_date ? format(new Date(assignment.due_date), 'yyyy-MM-dd') : '',
      max_score: assignment.max_score
    });
    setOpen(true);
  };

  const getStatusBadge = (assignment: Assignment) => {
    if (role !== 'student') return null;
    
    switch (assignment.submission_status) {
      case 'graded':
        return (
          <div className="flex items-center gap-2 text-success">
            <CheckCircle className="h-4 w-4" />
            <span className="text-sm font-medium">Đã chấm: {assignment.score}/{assignment.max_score}</span>
          </div>
        );
      case 'submitted':
        return (
          <div className="flex items-center gap-2 text-warning">
            <Clock className="h-4 w-4" />
            <span className="text-sm font-medium">Đã nộp</span>
          </div>
        );
      default:
        return (
          <div className="flex items-center gap-2 text-muted-foreground">
            <Clock className="h-4 w-4" />
            <span className="text-sm font-medium">Chưa nộp</span>
          </div>
        );
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
            <h1 className="text-3xl font-bold text-foreground mb-2">Bài tập</h1>
            <p className="text-muted-foreground">
              {role === 'student' 
                ? 'Xem và nộp bài tập của bạn' 
                : 'Quản lý bài tập cho các khóa học'}
            </p>
          </div>
          {(role === 'admin' || role === 'lecturer') && (
            <Dialog open={open} onOpenChange={setOpen}>
              <DialogTrigger asChild>
                <Button onClick={() => { setEditingAssignment(null); resetForm(); }}>
                  <PlusCircle className="h-4 w-4 mr-2" />
                  Tạo bài tập
                </Button>
              </DialogTrigger>
              <DialogContent className="max-w-2xl">
                <DialogHeader>
                  <DialogTitle>
                    {editingAssignment ? 'Chỉnh sửa bài tập' : 'Tạo bài tập mới'}
                  </DialogTitle>
                </DialogHeader>
                <form onSubmit={handleSubmit} className="space-y-4">
                  <div>
                    <Label htmlFor="title">Tiêu đề *</Label>
                    <Input
                      id="title"
                      value={formData.title}
                      onChange={(e) => setFormData({ ...formData, title: e.target.value })}
                      required
                    />
                  </div>
                  <div>
                    <Label htmlFor="course">Khóa học *</Label>
                    <Select
                      value={formData.course_id}
                      onValueChange={(value) => setFormData({ ...formData, course_id: value })}
                      required
                    >
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
                    <Label htmlFor="description">Mô tả</Label>
                    <Textarea
                      id="description"
                      value={formData.description}
                      onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                      rows={4}
                    />
                  </div>
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <Label htmlFor="due_date">Hạn nộp</Label>
                      <Input
                        id="due_date"
                        type="date"
                        value={formData.due_date}
                        onChange={(e) => setFormData({ ...formData, due_date: e.target.value })}
                      />
                    </div>
                    <div>
                      <Label htmlFor="max_score">Điểm tối đa</Label>
                      <Input
                        id="max_score"
                        type="number"
                        value={formData.max_score}
                        onChange={(e) => setFormData({ ...formData, max_score: parseInt(e.target.value) })}
                        min="1"
                        required
                      />
                    </div>
                  </div>
                  <div className="flex justify-end gap-2">
                    <Button type="button" variant="outline" onClick={() => setOpen(false)}>
                      Hủy
                    </Button>
                    <Button type="submit">
                      {editingAssignment ? 'Cập nhật' : 'Tạo'}
                    </Button>
                  </div>
                </form>
              </DialogContent>
            </Dialog>
          )}
        </div>
      </motion.div>

      {assignments.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12">
            <FileText className="h-12 w-12 text-muted-foreground mb-4" />
            <p className="text-muted-foreground">Chưa có bài tập nào</p>
          </CardContent>
        </Card>
      ) : (
        <div className="grid gap-4">
          {assignments.map((assignment, index) => (
            <motion.div
              key={assignment.id}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.05 }}
            >
              <Card className="shadow-card hover:shadow-hover transition-shadow">
                <CardHeader>
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <CardTitle className="text-xl mb-2">{assignment.title}</CardTitle>
                      <div className="flex items-center gap-4 text-sm text-muted-foreground">
                        <span className="font-medium text-primary">{assignment.course_name}</span>
                        {assignment.due_date && (
                          <div className="flex items-center gap-1">
                            <Calendar className="h-4 w-4" />
                            <span>Hạn: {format(new Date(assignment.due_date), 'dd/MM/yyyy')}</span>
                          </div>
                        )}
                        <span>Điểm: {assignment.max_score}</span>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      {getStatusBadge(assignment)}
                      {(role === 'admin' || role === 'lecturer') && (
                        <>
                          <Button
                            variant="ghost"
                            size="icon"
                            onClick={() => openEditDialog(assignment)}
                          >
                            <Edit className="h-4 w-4" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="icon"
                            onClick={() => handleDelete(assignment.id)}
                          >
                            <Trash2 className="h-4 w-4 text-destructive" />
                          </Button>
                        </>
                      )}
                    </div>
                  </div>
                </CardHeader>
                {assignment.description && (
                  <CardContent>
                    <p className="text-muted-foreground whitespace-pre-wrap">
                      {assignment.description}
                    </p>
                  </CardContent>
                )}
              </Card>
            </motion.div>
          ))}
        </div>
      )}
    </div>
  );
};

export default Assignments;
