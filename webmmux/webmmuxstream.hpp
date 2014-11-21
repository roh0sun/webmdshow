// Copyright (c) 2010 The WebM project authors. All Rights Reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree. An additional intellectual property rights grant can be found
// in the file PATENTS.  All contributing project authors may
// be found in the AUTHORS file in the root of the source tree.

#pragma once

#include <memory>
#include <string>

namespace webm_crypt_dll
{
	class WebmEncryptModule;
}

namespace WebmMuxLib
{

struct WebmEncryptModule_delete : public std::default_delete < webm_crypt_dll::WebmEncryptModule >
{
	void operator()(webm_crypt_dll::WebmEncryptModule* ptr);
};
typedef std::unique_ptr<webm_crypt_dll::WebmEncryptModule, WebmEncryptModule_delete> WebmEncryptModulePtr;

class Context;

class Stream
{
    Stream(Stream&);
    Stream& operator=(const Stream&);

public:
    virtual ~Stream();
    virtual void Final();  //grant last wishes

    virtual void WriteTrackEntry(int tn);

    virtual HRESULT Receive(IMediaSample*) = 0;
    virtual int EndOfStream() = 0;
    virtual void Flush() = 0;
    virtual bool Wait() const = 0;

    void SetTrackNumber(int);
    int GetTrackNumber() const;

    class Frame
    {
        Frame(const Frame&);
        Frame& operator=(const Frame&);

    protected:
        Frame();
        virtual ~Frame();
        virtual int GetLacing() const;

        void WriteBlock(
            const Stream&,
            ULONG cluster_timecode,
            bool simple_block,
			ULONG block_size,
			const BYTE* data_ptr,
			ULONG data_size) const;

        ULONG GetBlockSize() const;

    public:
        virtual bool IsKey() const = 0;

        void WriteSimpleBlock(
                    const Stream&,
                    ULONG cluster_timecode) const;

		void WriteSimpleRawBlock(
					const Stream&,
					ULONG cluster_timecode,
					const uint8_t* data_ptr,
					ULONG data_size) const;

        void WriteBlockGroup(
                    const Stream&,
                    ULONG cluster_timecode,
                    LONG prev_timecode,
                    ULONG duration) const;

        virtual ULONG GetTimecode() const = 0;
        virtual ULONG GetDuration() const = 0;  //TimecodeScale units

        virtual const BYTE* GetData() const = 0;
        virtual ULONG GetSize() const = 0;

        virtual void Release();
	};

    Context& m_context;

	bool EncryptFrame(const Frame* frame, const uint8_t*& encryptedData, size_t& encryptedDataSize);

protected:

    explicit Stream(Context&);

    typedef __int64 TrackUID_t;
    static TrackUID_t CreateTrackUID();

    int m_trackNumber;

    virtual void WriteTrackNumber(int);
    virtual void WriteTrackUID();
    virtual void WriteTrackType() = 0;
    virtual void WriteTrackName();
    virtual void WriteTrackCodecID() = 0;
    virtual void WriteTrackCodecPrivate();
    virtual void WriteTrackCodecName() = 0;
    virtual void WriteTrackSettings();
	virtual void WriteContentEncodings();
	virtual void WriteContentEncodingEncryption(const std::string& keyid);

	WebmEncryptModulePtr m_encryptModule;
	std::unique_ptr<uint8_t> m_encryptedData;
	size_t m_encryptedDataSize;
};


}  //end namespace WebmMuxLib
