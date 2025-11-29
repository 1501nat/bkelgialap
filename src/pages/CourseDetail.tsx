import { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import { motion } from 'framer-motion';
import { supabase } from '@/integrations/supabase/client';
import { useAuth } from '@/contexts/AuthContext';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { toast } from 'sonner';
import { BookOpen, FileText, Video, Bell, Users, PlusCircle, ExternalLink, Trash2 } from 'lucide-react';

interface Course {
  id: string;
  code: string;
  name: string;
  description: string | null;
  semester: string;
  year: number;
  lecturer_id: string;
  status: string;
}

interface CourseClass {
  id: string;
  class_code: string;
  class_name: string;
  max_students: number;
  created_at: string;
}

interface CourseMaterial {
  id: string;
  title: string;
  description: string | null;
  material_type: string;
  link_url: string;
  class_id: string | null;
  created_at: string;
}

const CourseDetail = () => {
  const { id } = useParams();
  const { role, user } = useAuth();
  const [course, setCourse] = useState<Course | null>(null);
  const [classes, setClasses] = useState<CourseClass[]>([]);
  const [materials, setMaterials] = useState<CourseMaterial[]>([]);
  const [loading, setLoading] = useState(true);
  const [classDialogOpen, setClassDialogOpen] = useState(false);
  const [materialDialogOpen, setMaterialDialogOpen] = useState(false);

  const [classForm, setClassForm] = useState({
    class_code: '',
    class_name: '',
    max_students: 50
  });

  const [materialForm, setMaterialForm] = useState({
    title: '',
    description: '',
    material_type: 'document',
    link_url: '',
    class_id: ''
  });

  useEffect(() => {
    if (id) {
      fetchCourseData();
    }
  }, [id]);

  const fetchCourseData = async () => {
    try {
      const { data: courseData, error: courseError } = await supabase
        .from('courses')
        .select('*')
        .eq('id', id)
        .single();

      if (courseError) throw courseError;
      setCourse(courseData);

      const { data: classesData, error: classesError } = await supabase
        .from('course_classes')
        .select('*')
        .eq('course_id', id)
        .order('created_at', { ascending: false });

      if (classesError) throw classesError;
      setClasses(classesData || []);

      const { data: materialsData, error: materialsError } = await supabase
        .from('course_materials')
        .select('*')
        .eq('course_id', id)
        .order('created_at', { ascending: false });

      if (materialsError) throw materialsError;
      setMaterials(materialsData || []);
    } catch (error: any) {
      toast.error('Lỗi khi tải thông tin khóa học');
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const handleCreateClass = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const { error } = await supabase
        .from('course_classes')
        .insert([{ ...classForm, course_id: id }]);

      if (error) throw error;

      toast.success('Tạo lớp học thành công');
      setClassDialogOpen(false);
      setClassForm({ class_code: '', class_name: '', max_students: 50 });
      fetchCourseData();
    } catch (error: any) {
      toast.error(error.message || 'Lỗi khi tạo lớp học');
    }
  };

  const handleCreateMaterial = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const { error } = await supabase
        .from('course_materials')
        .insert([{
          ...materialForm,
          course_id: id,
          class_id: materialForm.class_id || null,
          created_by: user?.id
        }]);

      if (error) throw error;

      toast.success('Thêm tài liệu thành công');
      setMaterialDialogOpen(false);
      setMaterialForm({
        title: '',
        description: '',
        material_type: 'document',
        link_url: '',
        class_id: ''
      });
      fetchCourseData();
    } catch (error: any) {
      toast.error(error.message || 'Lỗi khi thêm tài liệu');
    }
  };

  const handleDeleteMaterial = async (materialId: string) => {
    if (!confirm('Bạn có chắc muốn xóa tài liệu này?')) return;
    
    try {
      const { error } = await supabase
        .from('course_materials')
        .delete()
        .eq('id', materialId);

      if (error) throw error;
      toast.success('Đã xóa tài liệu');
      fetchCourseData();
    } catch (error: any) {
      toast.error('Lỗi khi xóa tài liệu');
    }
  };

  const getMaterialIcon = (type: string) => {
    switch (type) {
      case 'video': return <Video className="h-5 w-5 text-destructive" />;
      case 'document': return <FileText className="h-5 w-5 text-primary" />;
      default: return <ExternalLink className="h-5 w-5 text-muted-foreground" />;
    }
  };

  const isLecturerOrAdmin = role === 'lecturer' || role === 'admin';
  const canManage = isLecturerOrAdmin && (role === 'admin' || course?.lecturer_id === user?.id);

  if (loading) {
    return (
      <div className="container py-8 px-4">
        <div className="flex items-center justify-center h-64">
          <p className="text-muted-foreground">Đang tải...</p>
        </div>
      </div>
    );
  }

  if (!course) {
    return (
      <div className="container py-8 px-4">
        <p className="text-center text-muted-foreground">Không tìm thấy khóa học</p>
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
        <div className="flex items-center gap-3 mb-2">
          <BookOpen className="h-8 w-8 text-primary" />
          <h1 className="text-3xl font-bold text-foreground">{course.code} - {course.name}</h1>
          <Badge variant={course.status === 'approved' ? 'default' : 'secondary'}>
            {course.status === 'approved' ? 'Đã duyệt' : course.status === 'pending' ? 'Chờ duyệt' : 'Từ chối'}
          </Badge>
        </div>
        <p className="text-muted-foreground">{course.description || 'Chưa có mô tả'}</p>
        <p className="text-sm text-muted-foreground mt-2">
          Học kỳ {course.semester} - Năm {course.year}
        </p>
      </motion.div>

      <Tabs defaultValue="materials" className="w-full">
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="materials">
            <FileText className="h-4 w-4 mr-2" />
            Tài liệu
          </TabsTrigger>
          <TabsTrigger value="videos">
            <Video className="h-4 w-4 mr-2" />
            Video
          </TabsTrigger>
          <TabsTrigger value="assignments">
            <BookOpen className="h-4 w-4 mr-2" />
            Bài tập
          </TabsTrigger>
          <TabsTrigger value="classes">
            <Users className="h-4 w-4 mr-2" />
            Lớp học
          </TabsTrigger>
        </TabsList>

        <TabsContent value="materials" className="mt-6">
          <Card>
            <CardHeader>
              <div className="flex justify-between items-center">
                <CardTitle>Tài liệu học tập</CardTitle>
                {canManage && (
                  <Dialog open={materialDialogOpen} onOpenChange={setMaterialDialogOpen}>
                    <DialogTrigger asChild>
                      <Button size="sm">
                        <PlusCircle className="h-4 w-4 mr-2" />
                        Thêm tài liệu
                      </Button>
                    </DialogTrigger>
                    <DialogContent>
                      <DialogHeader>
                        <DialogTitle>Thêm tài liệu mới</DialogTitle>
                      </DialogHeader>
                      <form onSubmit={handleCreateMaterial} className="space-y-4">
                        <div>
                          <Label htmlFor="title">Tiêu đề</Label>
                          <Input
                            id="title"
                            value={materialForm.title}
                            onChange={(e) => setMaterialForm({ ...materialForm, title: e.target.value })}
                            required
                          />
                        </div>
                        <div>
                          <Label htmlFor="description">Mô tả</Label>
                          <Textarea
                            id="description"
                            value={materialForm.description}
                            onChange={(e) => setMaterialForm({ ...materialForm, description: e.target.value })}
                          />
                        </div>
                        <div>
                          <Label htmlFor="type">Loại tài liệu</Label>
                          <Select
                            value={materialForm.material_type}
                            onValueChange={(value) => setMaterialForm({ ...materialForm, material_type: value })}
                          >
                            <SelectTrigger>
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="document">Tài liệu</SelectItem>
                              <SelectItem value="video">Video</SelectItem>
                              <SelectItem value="link">Link</SelectItem>
                              <SelectItem value="other">Khác</SelectItem>
                            </SelectContent>
                          </Select>
                        </div>
                        <div>
                          <Label htmlFor="link">Link URL</Label>
                          <Input
                            id="link"
                            type="url"
                            value={materialForm.link_url}
                            onChange={(e) => setMaterialForm({ ...materialForm, link_url: e.target.value })}
                            placeholder="https://..."
                            required
                          />
                        </div>
                        <div>
                          <Label htmlFor="class">Lớp (tùy chọn)</Label>
                          <Select
                            value={materialForm.class_id}
                            onValueChange={(value) => setMaterialForm({ ...materialForm, class_id: value })}
                          >
                            <SelectTrigger>
                              <SelectValue placeholder="Tất cả lớp" />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="">Tất cả lớp</SelectItem>
                              {classes.map((cls) => (
                                <SelectItem key={cls.id} value={cls.id}>
                                  {cls.class_code} - {cls.class_name}
                                </SelectItem>
                              ))}
                            </SelectContent>
                          </Select>
                        </div>
                        <Button type="submit" className="w-full">Thêm</Button>
                      </form>
                    </DialogContent>
                  </Dialog>
                )}
              </div>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {materials.filter(m => m.material_type === 'document').map((material) => (
                  <div key={material.id} className="flex items-center justify-between p-4 rounded-lg bg-accent hover:bg-accent/80 transition-colors">
                    <div className="flex items-center gap-3 flex-1">
                      {getMaterialIcon(material.material_type)}
                      <div>
                        <h3 className="font-medium">{material.title}</h3>
                        {material.description && (
                          <p className="text-sm text-muted-foreground">{material.description}</p>
                        )}
                      </div>
                    </div>
                    <div className="flex gap-2">
                      <Button size="sm" variant="outline" asChild>
                        <a href={material.link_url} target="_blank" rel="noopener noreferrer">
                          <ExternalLink className="h-4 w-4 mr-1" />
                          Mở
                        </a>
                      </Button>
                      {canManage && (
                        <Button size="sm" variant="ghost" onClick={() => handleDeleteMaterial(material.id)}>
                          <Trash2 className="h-4 w-4 text-destructive" />
                        </Button>
                      )}
                    </div>
                  </div>
                ))}
                {materials.filter(m => m.material_type === 'document').length === 0 && (
                  <p className="text-center py-8 text-muted-foreground">Chưa có tài liệu nào</p>
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="videos" className="mt-6">
          <Card>
            <CardHeader>
              <div className="flex justify-between items-center">
                <CardTitle>Video bài giảng</CardTitle>
                {canManage && (
                  <Button size="sm" onClick={() => {
                    setMaterialForm({ ...materialForm, material_type: 'video' });
                    setMaterialDialogOpen(true);
                  }}>
                    <PlusCircle className="h-4 w-4 mr-2" />
                    Thêm video
                  </Button>
                )}
              </div>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {materials.filter(m => m.material_type === 'video').map((material) => (
                  <div key={material.id} className="flex items-center justify-between p-4 rounded-lg bg-accent hover:bg-accent/80 transition-colors">
                    <div className="flex items-center gap-3 flex-1">
                      {getMaterialIcon(material.material_type)}
                      <div>
                        <h3 className="font-medium">{material.title}</h3>
                        {material.description && (
                          <p className="text-sm text-muted-foreground">{material.description}</p>
                        )}
                      </div>
                    </div>
                    <div className="flex gap-2">
                      <Button size="sm" variant="outline" asChild>
                        <a href={material.link_url} target="_blank" rel="noopener noreferrer">
                          <ExternalLink className="h-4 w-4 mr-1" />
                          Xem
                        </a>
                      </Button>
                      {canManage && (
                        <Button size="sm" variant="ghost" onClick={() => handleDeleteMaterial(material.id)}>
                          <Trash2 className="h-4 w-4 text-destructive" />
                        </Button>
                      )}
                    </div>
                  </div>
                ))}
                {materials.filter(m => m.material_type === 'video').length === 0 && (
                  <p className="text-center py-8 text-muted-foreground">Chưa có video nào</p>
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="assignments" className="mt-6">
          <Card>
            <CardHeader>
              <CardTitle>Bài tập</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-center py-8 text-muted-foreground">Chức năng bài tập đang được phát triển</p>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="classes" className="mt-6">
          <Card>
            <CardHeader>
              <div className="flex justify-between items-center">
                <CardTitle>Danh sách lớp học</CardTitle>
                {canManage && (
                  <Dialog open={classDialogOpen} onOpenChange={setClassDialogOpen}>
                    <DialogTrigger asChild>
                      <Button size="sm">
                        <PlusCircle className="h-4 w-4 mr-2" />
                        Tạo lớp mới
                      </Button>
                    </DialogTrigger>
                    <DialogContent>
                      <DialogHeader>
                        <DialogTitle>Tạo lớp học mới</DialogTitle>
                      </DialogHeader>
                      <form onSubmit={handleCreateClass} className="space-y-4">
                        <div>
                          <Label htmlFor="class_code">Mã lớp</Label>
                          <Input
                            id="class_code"
                            value={classForm.class_code}
                            onChange={(e) => setClassForm({ ...classForm, class_code: e.target.value })}
                            placeholder="VD: L01"
                            required
                          />
                        </div>
                        <div>
                          <Label htmlFor="class_name">Tên lớp</Label>
                          <Input
                            id="class_name"
                            value={classForm.class_name}
                            onChange={(e) => setClassForm({ ...classForm, class_name: e.target.value })}
                            placeholder="VD: Lớp 1"
                            required
                          />
                        </div>
                        <div>
                          <Label htmlFor="max_students">Số lượng sinh viên tối đa</Label>
                          <Input
                            id="max_students"
                            type="number"
                            value={classForm.max_students}
                            onChange={(e) => setClassForm({ ...classForm, max_students: parseInt(e.target.value) })}
                            min="1"
                            required
                          />
                        </div>
                        <Button type="submit" className="w-full">Tạo lớp</Button>
                      </form>
                    </DialogContent>
                  </Dialog>
                )}
              </div>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {classes.map((cls) => (
                  <div key={cls.id} className="flex items-center justify-between p-4 rounded-lg bg-accent">
                    <div className="flex items-center gap-3">
                      <Users className="h-5 w-5 text-primary" />
                      <div>
                        <h3 className="font-medium">{cls.class_code} - {cls.class_name}</h3>
                        <p className="text-sm text-muted-foreground">
                          Sĩ số tối đa: {cls.max_students} sinh viên
                        </p>
                      </div>
                    </div>
                  </div>
                ))}
                {classes.length === 0 && (
                  <p className="text-center py-8 text-muted-foreground">Chưa có lớp học nào</p>
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default CourseDetail;
