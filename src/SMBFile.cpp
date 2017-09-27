/*
 *      Copyright (C) 2005-2013 Team XBMC
 *      http://xbmc.org
 *
 *  This Program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 *  This Program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with XBMC; see the file COPYING.  If not, see
 *  <http://www.gnu.org/licenses/>.
 *
 */

#include <fcntl.h>
#include <sstream>

#include "SMBFile.h"
#include <libsmbclient.h>

std::string CSMBFile::GetAuthenticatedPath(const VFSURL& url)
{
  std::string result = CSMB2::Get().URLEncode(url.domain, url.hostname, url.filename, url.username, url.password);

  return result;
}

bool CSMBFile::IsValidFile(const std::string& strFileName)
{
  if (strFileName.find('/') == std::string::npos || /* doesn't have sharename */
      strFileName.substr(strFileName.size()-2) == "/." || /* not current folder */
      strFileName.substr(strFileName.size()-3) == "/..")  /* not parent folder */
    return false;
  return true;
}

void* CSMBFile::Open(const VFSURL& url)
{
  CSMB2::Get().Init();
  CSMB2::Get().AddActiveConnection();
  if (!IsValidFile(url.filename))
  {
    kodi::Log(ADDON_LOG_INFO, "FileSmb->Open: Bad URL : '%s'",url.redacted);
    return NULL;
  }
  int fd = -1;
  std::string filename = GetAuthenticatedPath(url);
  P8PLATFORM::CLockObject lock(CSMB2::Get());
  fd = smbc_open(filename.c_str(), O_RDONLY, 0);
  if (fd == -1)
  {
    kodi::Log(ADDON_LOG_INFO, "FileSmb->Open: Unable to open file : '%s'\nunix_err:'%x' error : '%s'", url.redacted, errno, strerror(errno));
    return NULL;
  }
  kodi::Log(ADDON_LOG_DEBUG,"CSMB2File::Open - opened %s, fd=%d", url.filename, fd);
  struct stat tmpBuffer;
  if (smbc_stat(filename.c_str(), &tmpBuffer) < 0)
  {
    smbc_close(fd);
    return NULL;
  }
  int64_t ret = smbc_lseek(fd, 0, SEEK_SET);
  if (ret < 0)
  {
    smbc_close(fd);
    return NULL;
  }
  SMBContext* result = new SMBContext;
  result->fd = fd;
  result->size = tmpBuffer.st_size;
  return result;
}

bool CSMBFile::Close(void* context)
{
  SMBContext* ctx = (SMBContext*)context;
  kodi::Log(ADDON_LOG_DEBUG,"CSMB2File::Close closing fd %d", ctx->fd);
  P8PLATFORM::CLockObject lock(CSMB2::Get());
  smbc_close(ctx->fd);
  CSMB2::Get().AddIdleConnection();
}

ssize_t CSMBFile::Read(void* context, void* lpBuf, size_t uiBufSize)
{
  SMBContext* ctx = (SMBContext*)context;
  if (ctx->fd == -1)
    return 0;

  P8PLATFORM::CLockObject lock(CSMB2::Get()); // Init not called since it has to be "inited" by now
  CSMB2::Get().SetActivityTime();
  /* work around stupid bug in samba */
  /* some samba servers has a bug in it where the */
  /* 17th bit will be ignored in a request of data */
  /* this can lead to a very small return of data */
  /* also worse, a request of exactly 64k will return */
  /* as if eof, client has a workaround for windows */
  /* thou it seems other servers are affected too */
  if( uiBufSize >= 64*1024-2 )
    uiBufSize = 64*1024-2;

  int bytesRead = smbc_read(ctx->fd, lpBuf, (int)uiBufSize);

  if ( bytesRead < 0 && errno == EINVAL )
  {
    kodi::Log(ADDON_LOG_ERROR, "%s - Error( %d, %d, %s ) - Retrying", __FUNCTION__, bytesRead, errno, strerror(errno));
    bytesRead = smbc_read(ctx->fd, lpBuf, (int)uiBufSize);
  }

  if ( bytesRead < 0 )
  {
    kodi::Log(ADDON_LOG_ERROR, "%s - Error( %d, %d, %s )", __FUNCTION__, bytesRead, errno, strerror(errno));
    return 0;
  }

  return bytesRead;
}

int64_t CSMBFile::GetLength(void* context)
{
  SMBContext* ctx = (SMBContext*)context;

  return ctx->size;
}

int64_t CSMBFile::GetPosition(void* context)
{
  SMBContext* ctx = (SMBContext*)context;
  if (ctx->fd == -1)
    return 0;
  CSMB2::Get().Init();
  P8PLATFORM::CLockObject lock(CSMB2::Get());
  int64_t pos = smbc_lseek(ctx->fd, 0, SEEK_CUR);
  if ( pos < 0 )
    return 0;
  return pos;
}

int64_t CSMBFile::Seek(void* context, int64_t iFilePosition, int iWhence)
{
  SMBContext* ctx = (SMBContext*)context;
  if (ctx->fd == -1)
    return -1;

  P8PLATFORM::CLockObject lock(CSMB2::Get()); // Init not called since it has to be "inited" by now
  CSMB2::Get().SetActivityTime();
  int64_t pos = smbc_lseek(ctx->fd, iFilePosition, iWhence);

  if ( pos < 0 )
  {
    kodi::Log(ADDON_LOG_ERROR, "%s - Error( seekpos: %" PRId64 ", whence: %i, fsize: %" PRId64 ", %s)",
              __FUNCTION__, iFilePosition, iWhence, ctx->size, strerror(errno));
    return -1;
  }

  return (int64_t)pos;
}

bool CSMBFile::Exists(const VFSURL& url)
{
  // we can't open files like smb://file.f or smb://server/file.f
  // if a file matches the if below return false, it can't exist on a samba share.
  if (!IsValidFile(url.filename))
    return false;

  CSMB2::Get().Init();
  std::string strFileName = GetAuthenticatedPath(url);

  struct stat info;

  CSMB2& smb = CSMB2::Get();

  P8PLATFORM::CLockObject lock(smb);
  int iResult = smbc_stat(strFileName.c_str(), &info);

  if (iResult < 0)
    return false;

  return true;
}

int CSMBFile::Stat(const VFSURL& url, struct __stat64* buffer)
{
  CSMB2::Get().Init();
  std::string strFileName = GetAuthenticatedPath(url);
  P8PLATFORM::CLockObject lock(CSMB2::Get());

  struct stat tmpBuffer = {0};
  int iResult = smbc_stat(strFileName.c_str(), &tmpBuffer);

  if (buffer)
  {
    memset(buffer, 0, sizeof(struct __stat64));
    buffer->st_dev = tmpBuffer.st_dev;
    buffer->st_ino = tmpBuffer.st_ino;
    buffer->st_mode = tmpBuffer.st_mode;
    buffer->st_nlink = tmpBuffer.st_nlink;
    buffer->st_uid = tmpBuffer.st_uid;
    buffer->st_gid = tmpBuffer.st_gid;
    buffer->st_rdev = tmpBuffer.st_rdev;
    buffer->st_size = tmpBuffer.st_size;
    buffer->st_atime = tmpBuffer.st_atime;
    buffer->st_mtime = tmpBuffer.st_mtime;
    buffer->st_ctime = tmpBuffer.st_ctime;
  }

  return iResult;
}

int CSMBFile::IoControl(void* context, XFILE::EIoControl request, void* param)
{
  return -1;
}

void CSMBFile::ClearOutIdle()
{
  CSMB2::Get().CheckIfIdle();
}

void CSMBFile::DisconnectAll()
{
  CSMB2::Get().Deinit();
}

bool CSMBFile::DirectoryExists(const VFSURL& url)
{
  P8PLATFORM::CLockObject lock(CSMB2::Get());
  CSMB2::Get().Init();

  std::string strFileName = CSMB2::Get().URLEncode(url.domain, url.hostname, url.filename,
                                                  url.username, url.password);

  struct stat info;
  if (smbc_stat(strFileName.c_str(), &info) != 0)
    return false;

  return (info.st_mode & S_IFDIR) ? true : false;
}

bool CSMBFile::GetDirectory(const VFSURL& url, std::vector<kodi::vfs::CDirEntry>& items, CVFSCallbacks callbacks)
{
  CSMB2::Get().AddActiveConnection();

  P8PLATFORM::CLockObject lock(CSMB2::Get());
  CSMB2::Get().Init();
  lock.Unlock();

  std::string strFileName = CSMB2::Get().URLEncode(url.domain, url.hostname,
                                                   url.filename,
                                                   url.username, url.password);
  // remove the / or \ at the end. the samba library does not strip them off
  // don't do this for smb:// !!
  std::string s = strFileName;
  int len = s.length();
  if (len > 1 && s.at(len - 2) != '/' &&
      (s.at(len - 1) == '/' || s.at(len - 1) == '\\'))
  {
    s.erase(len - 1, 1);
  }

  kodi::Log(ADDON_LOG_DEBUG, "%s - Using authentication url %s", __FUNCTION__, url.redacted);
  lock.Lock();
  int fd = smbc_opendir(s.c_str());
  lock.Unlock();

  while (fd < 0) /* only to avoid goto in following code */
  {
    char cError[1024];
    if (errno == EACCES)
    {
      callbacks.RequireAuthentication(url.url);
      break;
    }
    if (errno == ENODEV || errno == ENOENT)
    {
      std::string str770 = kodi::GetLocalizedString(770);
      sprintf(cError, str770.c_str(), errno);
    }
    else
      strcpy(cError,strerror(errno));

    std::string str257 = kodi::GetLocalizedString(257);
    callbacks.SetErrorDialog(str257, cError, NULL, NULL);
    break;
  }
  if (fd < 0)
  {
    kodi::Log(ADDON_LOG_ERROR, "SMBDirectory->GetDirectory: Unable to open directory : '%s'\nunix_err:'%x' error : '%s'", url.redacted, errno, strerror(errno));
    return false;
  }

  return true;
}

bool CSMBFile::CreateDirectory(const VFSURL& url)
{
  bool success = true;
  P8PLATFORM::CLockObject lock(CSMB2::Get());
  CSMB2::Get().Init();

  std::string strFileName = CSMB2::Get().URLEncode(url.domain, url.hostname, url.filename,
                                                  url.username, url.password);

  int result = smbc_mkdir(strFileName.c_str(), 0);
  success = (result == 0 || EEXIST == errno);
  if(!success)
    kodi::Log(ADDON_LOG_ERROR, "%s - Error( %s )", __FUNCTION__, strerror(errno));

  return success;
}

bool CSMBFile::RemoveDirectory(const VFSURL& url)
{
  P8PLATFORM::CLockObject lock(CSMB2::Get());
  CSMB2::Get().Init();

  std::string strFileName = CSMB2::Get().URLEncode(url.domain, url.hostname, url.filename,
                                                  url.username, url.password);

  int result = smbc_rmdir(strFileName.c_str());

  if(result != 0 && errno != ENOENT)
  {
    kodi::Log(ADDON_LOG_ERROR, "%s - Error( %s )", __FUNCTION__, strerror(errno));
    return false;
  }

  return true;
}

int CSMBFile::Truncate(void* context, int64_t size)
{
/*
 * This would force us to be dependant on SMBv3.2 which is GPLv3
 * This is only used by the TagLib writers, which are not currently in use
 * So log and warn until we implement TagLib writing & can re-implement this better.
  CSingleLock lock(smb); // Init not called since it has to be "inited" by now

#if defined(TARGET_ANDROID)
  int iResult = 0;
#else
  int iResult = smbc_ftruncate(m_fd, size);
#endif
*/
  kodi::Log(ADDON_LOG_ERROR, "%s - Warning(smbc_ftruncate called and not implemented)", __FUNCTION__);
  return 0;
}

ssize_t CSMBFile::Write(void* context, const void* lpBuf, size_t uiBufSize)
{
  SMBContext* ctx = (SMBContext*)context;
  if (ctx->fd == -1)
    return -1;

  ssize_t dwNumberOfBytesWritten = 0;

  // lpBuf can be safely casted to void* since xmbc_write will only read from it.
  CSMB2::Get().Init();
  P8PLATFORM::CLockObject lock(CSMB2::Get());
  dwNumberOfBytesWritten = smbc_write(ctx->fd, (void*)lpBuf, uiBufSize);

  return dwNumberOfBytesWritten;
}

bool CSMBFile::Delete(const VFSURL& url)
{
  CSMB2::Get().Init();
  std::string strFile = GetAuthenticatedPath(url);

  P8PLATFORM::CLockObject lock(CSMB2::Get());

  int result = smbc_unlink(strFile.c_str());

  if(result != 0)
    kodi::Log(ADDON_LOG_ERROR, "%s - Error( %s )", __FUNCTION__, strerror(errno));

  return (result == 0);
}

bool CSMBFile::Rename(const VFSURL& url, const VFSURL& url2)
{
  CSMB2::Get().Init();
  std::string strFile = GetAuthenticatedPath(url);
  std::string strFileNew = GetAuthenticatedPath(url2);
  P8PLATFORM::CLockObject lock(CSMB2::Get());

  int result = smbc_rename(strFile.c_str(), strFileNew.c_str());

  if(result != 0)
    kodi::Log(ADDON_LOG_ERROR, "%s - Error( %s )", __FUNCTION__, strerror(errno));

  return (result == 0);
}

void* CSMBFile::OpenForWrite(const VFSURL& url, bool bOverWrite)
{
  CSMB2::Get().Init();
  // we can't open files like smb://file.f or smb://server/file.f
  // if a file matches the if below return false, it can't exist on a samba share.
  if (!IsValidFile(url.filename))
    return NULL;

  std::string strFileName = GetAuthenticatedPath(url);
  P8PLATFORM::CLockObject lock(CSMB2::Get());

  SMBContext* result = new SMBContext;
  if (bOverWrite)
  {
    kodi::Log(ADDON_LOG_INFO, "FileSmb::OpenForWrite() called with overwriting enabled! - %s", strFileName.c_str());
    result->fd = smbc_creat(strFileName.c_str(), 0);
  }
  else
  {
    result->fd = smbc_open(strFileName.c_str(), O_RDWR, 0);
  }

  if (result->fd == -1)
  {
    // write error to logfile
    kodi::Log(ADDON_LOG_ERROR, "FileSmb->Open: Unable to open file : '%s'\nunix_err:'%x' error : '%s'", strFileName.c_str(), errno, strerror(errno));
    delete result;
    return NULL;
  }

  // We've successfully opened the file!
  return result;
}
