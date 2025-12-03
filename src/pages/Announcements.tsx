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
import { Switch } from '@/components/ui/switch';
import { toast } from 'sonner';
import { Bell, PlusCircle, Edit, Trash2, Globe } from 'lucide-react';
import { format } from 'date-fns';

interface Announcement {
  id: string;
  title: string;
  content: string;
  course_id: string | null;
  is_global: boolean;
  created_by: string;
  created_at: string;
  course_name?: string;
  author_name?: string;
  status?: string;
}

interface AnnouncementCardProps {
  announcement: Announcement;
  index: number;
  canEdit: boolean;
  onEdit: (announcement: Announcement) => void;
  onDelete: (id: string) => void;
}

const AnnouncementCard = ({ announcement, index, canEdit, onEdit, onDelete }: AnnouncementCardProps) => (
  <motion.div
    initial={{ opacity: 0, y: 20 }}
    animate={{ opacity: 1, y: 0 }}
    transition={{ delay: index * 0.05 }}
  >
    <Card className="shadow-card hover:shadow-hover transition-shadow">
      <CardHeader>
        <div className="flex items-start justify-between gap-4">
          <div className="flex-1">
            <div className="flex items-center gap-2 flex-wrap mb-2">
              <CardTitle className="text-xl">{announcement.title}</CardTitle>
              {announcement.status && announcement.status !== 'approved' && (
                <span className="inline-flex items-center rounded-full bg-muted px-2 py-0.5 text-xs text-muted-foreground">
                  {announcement.status === 'pending' ? 'Chờ duyệt' : 'Đã từ chối'}
                </span>
              )}
            </div>
            <div className="flex items-center gap-4 text-sm text-muted-foreground">
              <span>{announcement.author_name}</span>
              {announcement.course_name && (
                <span className="text-primary">{announcement.course_name}</span>
              )}
              <span>{format(new Date(announcement.created_at), 'dd/MM/yyyy HH:mm')}</span>
            </div>
          </div>
          {canEdit && (
            <div className="flex items-center gap-2">
              <Button
                variant="ghost"
                size="icon"
                onClick={() => onEdit(announcement)}
              >
                <Edit className="h-4 w-4" />
              </Button>
              <Button
                variant="ghost"
                size="icon"
                onClick={() => onDelete(announcement.id)}
              >
                <Trash2 className="h-4 w-4 text-destructive" />
              </Button>
            </div>
          )}
        </div>
      </CardHeader>
      <CardContent>
        <p className="text-foreground whitespace-pre-wrap">{announcement.content}</p>
      </CardContent>
    </Card>
  </motion.div>
);

const STATUS_COLUMN_ERROR = "'status' column";

const Announcements = () => {
  const { role, user } = useAuth();
  const [announcements, setAnnouncements] = useState<Announcement[]>([]);
  const [courses, setCourses] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [open, setOpen] = useState(false);
  const [editingAnnouncement, setEditingAnnouncement] = useState<Announcement | null>(null);
  const [supportsStatus, setSupportsStatus] = useState(true);
  const [formData, setFormData] = useState({
    title: '',
    content: '',
    course_id: '',
    is_global: false
  });

  useEffect(() => {
    fetchData();
  }, [role, user]);

  const fetchData = async () => {
    try {
      // Fetch courses for filter
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

      // Fetch announcements
      const announcementsData = await fetchAnnouncements();

      // Filter announcements based on role
      let filteredAnnouncements = announcementsData || [];
      
      if (role === 'student') {
        const courseIds = coursesData?.map(c => c.id) || [];
        filteredAnnouncements = filteredAnnouncements.filter((a: any) =>
          (supportsStatus ? a.status === 'approved' : true) &&
          (a.is_global || (a.course_id && courseIds.includes(a.course_id)))
        );
      } else if (role === 'lecturer') {
        const courseIds = coursesData?.map(c => c.id) || [];
        filteredAnnouncements = filteredAnnouncements.filter((a: any) =>
          a.is_global
            ? (supportsStatus ? a.status === 'approved' : true)
            : (a.course_id && courseIds.includes(a.course_id)) || a.created_by === user?.id
        );
      } else {
        // admin sees all
        filteredAnnouncements = announcementsData || [];
      }

      // Add course and author names
      const announcementsWithDetails = await Promise.all(
        filteredAnnouncements.map(async (announcement) => {
          const course = coursesData?.find(c => c.id === announcement.course_id);
          
          const { data: profile } = await supabase
            .from('profiles')
            .select('full_name')
            .eq('id', announcement.created_by)
            .single();
          
          return {
            ...announcement,
            course_name: course?.name,
            author_name: profile?.full_name
          };
        })
      );

      setAnnouncements(announcementsWithDetails);
    } catch (error: any) {
      toast.error('Lỗi khi tải danh sách thông báo');
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const fetchAnnouncements = async () => {
    const { data, error } = await supabase
      .from('announcements')
      .select('*')
      .order('created_at', { ascending: false });

    if (error) {
      if (error.message?.includes(STATUS_COLUMN_ERROR)) {
        setSupportsStatus(false);
        const { data: fallbackData, error: fallbackError } = await supabase
          .from('announcements')
          .select('id, title, content, course_id, is_global, created_by, created_at')
          .order('created_at', { ascending: false });
        if (fallbackError) throw fallbackError;
        return fallbackData || [];
      }
      throw error;
    }

    if (!supportsStatus) setSupportsStatus(true);
    return data || [];
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    try {
      const payloadBase = {
        ...formData,
        course_id: formData.is_global ? null : formData.course_id || null,
        created_by: user?.id,
      };

      const buildPayload = () => {
        if (!supportsStatus) return payloadBase;
        return {
          ...payloadBase,
          status: formData.is_global && role !== 'admin' ? 'pending' : 'approved',
        };
      };

      const mutate = async (payload: typeof payloadBase & { status?: string }) => {
        if (editingAnnouncement) {
          return supabase.from('announcements').update(payload).eq('id', editingAnnouncement.id);
        }
        return supabase.from('announcements').insert([payload]);
      };

      let result = await mutate(buildPayload());

      if (result.error && result.error.message?.includes(STATUS_COLUMN_ERROR)) {
        setSupportsStatus(false);
        result = await mutate(payloadBase);
      }

      if (result.error) throw result.error;

      toast.success(editingAnnouncement ? 'Cập nhật thông báo thành công' : 'Tạo thông báo thành công');

      setOpen(false);
      setEditingAnnouncement(null);
      resetForm();
      fetchData();
    } catch (error: any) {
      toast.error(error.message || 'Có lỗi xảy ra');
    }
  };

  const handleDelete = async (id: string) => {
    if (!confirm('Bạn có chắc chắn muốn xóa thông báo này?')) return;
    
    try {
      const { error } = await supabase
        .from('announcements')
        .delete()
        .eq('id', id);

      if (error) throw error;
      toast.success('Xóa thông báo thành công');
      fetchData();
    } catch (error: any) {
      toast.error(error.message || 'Có lỗi xảy ra');
    }
  };

  const resetForm = () => {
    setFormData({
      title: '',
      content: '',
      course_id: '',
      is_global: false
    });
  };

  const openEditDialog = (announcement: Announcement) => {
    setEditingAnnouncement(announcement);
    setFormData({
      title: announcement.title,
      content: announcement.content,
      course_id: announcement.course_id || '',
      is_global: announcement.is_global
    });
    setOpen(true);
  };

  const canEdit = (announcement: Announcement) => {
    return role === 'admin' || announcement.created_by === user?.id;
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
            <h1 className="text-3xl font-bold text-foreground mb-2">Thông báo</h1>
            <p className="text-muted-foreground">
              {role === 'student' 
                ? 'Xem các thông báo từ trường và giảng viên' 
                : 'Quản lý thông báo cho sinh viên'}
            </p>
          </div>
          {(role === 'admin' || role === 'lecturer') && (
            <Dialog open={open} onOpenChange={setOpen}>
              <DialogTrigger asChild>
                <Button onClick={() => { setEditingAnnouncement(null); resetForm(); }}>
                  <PlusCircle className="h-4 w-4 mr-2" />
                  Tạo thông báo
                </Button>
              </DialogTrigger>
              <DialogContent className="max-w-2xl">
                <DialogHeader>
                  <DialogTitle>
                    {editingAnnouncement ? 'Chỉnh sửa thông báo' : 'Tạo thông báo mới'}
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
                    <Label htmlFor="content">Nội dung *</Label>
                    <Textarea
                      id="content"
                      value={formData.content}
                      onChange={(e) => setFormData({ ...formData, content: e.target.value })}
                      rows={6}
                      required
                    />
                  </div>
                  {(role === 'admin' || role === 'lecturer') && (
                    <div className="space-y-1.5">
                      <div className="flex items-center gap-2">
                        <Switch
                          id="is_global"
                          checked={formData.is_global}
                          onCheckedChange={(checked) => setFormData({ ...formData, is_global: checked })}
                        />
                        <Label htmlFor="is_global" className="cursor-pointer">
                          Thông báo toàn trường
                        </Label>
                      </div>
                      {role === 'lecturer' && (
                        <p className="text-xs text-muted-foreground">
                          Thông báo toàn trường cần được admin duyệt thủ công.
                        </p>
                      )}
                    </div>
                  )}
                  {!formData.is_global && (
                    <div>
                      <Label htmlFor="course">Khóa học (tùy chọn)</Label>
                      <Select
                        value={formData.course_id}
                        onValueChange={(value) => setFormData({ ...formData, course_id: value })}
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
                  )}
                  <div className="flex justify-end gap-2">
                    <Button type="button" variant="outline" onClick={() => setOpen(false)}>
                      Hủy
                    </Button>
                    <Button type="submit">
                      {editingAnnouncement ? 'Cập nhật' : 'Tạo'}
                    </Button>
                  </div>
                </form>
              </DialogContent>
            </Dialog>
          )}
        </div>
      </motion.div>

      {announcements.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12">
            <Bell className="h-12 w-12 text-muted-foreground mb-4" />
            <p className="text-muted-foreground">Chưa có thông báo nào</p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-8">
          {/* Global Announcements */}
          {announcements.filter(a => a.is_global).length > 0 && (
            <div>
              <div className="flex items-center gap-2 mb-4">
                <Globe className="h-5 w-5 text-primary" />
                <h2 className="text-xl font-semibold">Thông báo toàn trường</h2>
              </div>
              <div className="grid gap-4">
                {announcements.filter(a => a.is_global).map((announcement, index) => (
                  <AnnouncementCard
                    key={announcement.id}
                    announcement={announcement}
                    index={index}
                    canEdit={canEdit(announcement)}
                    onEdit={openEditDialog}
                    onDelete={handleDelete}
                  />
                ))}
              </div>
            </div>
          )}

          {/* Course Announcements */}
          {announcements.filter(a => !a.is_global).length > 0 && (
            <div>
              <div className="flex items-center gap-2 mb-4">
                <Bell className="h-5 w-5 text-primary" />
                <h2 className="text-xl font-semibold">Thông báo môn học</h2>
              </div>
              <div className="grid gap-4">
                {announcements.filter(a => !a.is_global).map((announcement, index) => (
                  <AnnouncementCard
                    key={announcement.id}
                    announcement={announcement}
                    index={index}
                    canEdit={canEdit(announcement)}
                    onEdit={openEditDialog}
                    onDelete={handleDelete}
                  />
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default Announcements;
