class IOCExtract:
    def extract_section(text, start_markers, end_markers):
        try:
            if isinstance(start_markers, str):
                start_markers = [start_markers]
            
            start_idx = -1
            matched_marker = None
            for marker in start_markers:
                idx = text.find(marker)
                if idx != -1:
                    start_idx = idx
                    matched_marker = marker
                    break
            
            if start_idx == -1:
                return "Not Found!"
            
            start_idx += len(matched_marker)
            
            if isinstance(end_markers, str):
                end_markers = [end_markers]
            
            end_idx = len(text)
            for marker in end_markers:
                idx = text.find(marker, start_idx)
                if idx != -1 and idx < end_idx:
                    end_idx = idx
            
            section = text[start_idx:end_idx].strip()
            section = '\n'.join([line.strip() for line in section.split('\n') if line.strip()])
            
            return section[:3000] if section else "Not Found!"
        except:
            return "Not Found!"
